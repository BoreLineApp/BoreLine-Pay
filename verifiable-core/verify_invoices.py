#!/usr/bin/env python3
"""Independent invoice-address verifier for BoreLine Pay merchants.

WHAT IT DOES
    Pulls your own invoice list from the BoreLine API and, using YOUR zpub
    (the one from your hardware wallet, never one the server hands you),
    re-derives the receiving address for every invoice and confirms it matches
    the address the server issued. If any address does not derive from your key,
    it is flagged loudly. A compromised server cannot pass this check by lying,
    because the key the check runs against comes from you, not from BoreLine.

    This does not touch your funds, needs no private key, and makes no change to
    anything. It reads public receiving addresses and does maths on your machine.

WHAT YOU NEED (paste once into verifier_config.json, or pass as flags/env)
    zpub           your account zpub, exported from your wallet (starts zpub...)
    verify_token   a verification token: generate it on your dashboard's Verify
                   page. It unlocks only your address feed, nothing else.
    api_base       https://api.borelinepay.uk  (default)

    Optionally (--confirm) it also reconciles PAYMENTS: for every paid or
    pending invoice it checks what the chain actually received, via a public
    Esplora explorer or your OWN node (a self-hosted Esplora, or your Electrum
    server), and flags a "paid" the server claims with no on-chain funds.

USAGE
    python verify_invoices.py                 # verify addresses only
    python verify_invoices.py --watch 300     # re-check every 300 seconds
    python verify_invoices.py --confirm       # also reconcile payments via mempool.space
    python verify_invoices.py --confirm --esplora-url http://my-mempool.local   # your own Esplora
    python verify_invoices.py --confirm --source electrum --electrum-host 10.0.0.5  # your own node
    BORELINE_ZPUB=zpub... BORELINE_VERIFY_TOKEN=... python verify_invoices.py

EXIT CODE
    0  every checked address matched your key
    1  at least one mismatch (wire this into an alert / cron and page yourself)
    2  a configuration or network problem, nothing verified

This file uses only the Python standard library plus derive.py sitting next to
it (the same audited derivation BoreLine publishes). No third-party packages.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request

import derive  # the sibling module in verifiable-core/

DEFAULT_API = "https://api.borelinepay.uk"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifier_config.json")


def _load_config():
    """Merge, in order of precedence: CLI flags > env vars > verifier_config.json."""
    cfg = {"api_base": DEFAULT_API, "zpub": "", "verify_token": "", "previous_zpubs": [],
           "source": "esplora", "esplora_url": "https://mempool.space", "xcheck_url": "",
           "electrum_host": "", "electrum_port": 50002, "electrum_ssl": True}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg.update({k: v for k, v in json.load(f).items() if v})
        except Exception as e:
            print(f"[warn] could not read {CONFIG_FILE}: {e}")
    cfg["api_base"] = os.environ.get("BORELINE_API", cfg["api_base"])
    cfg["zpub"] = os.environ.get("BORELINE_ZPUB", cfg["zpub"])
    cfg["verify_token"] = os.environ.get("BORELINE_VERIFY_TOKEN", cfg["verify_token"])
    return cfg


def _write_config_template():
    tmpl = {"api_base": DEFAULT_API, "zpub": "zpub...paste yours here...",
            "verify_token": "generate this on your dashboard Verify page"}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(tmpl, f, indent=2)
    print(f"Wrote a template to {CONFIG_FILE}. Fill in your zpub and verification token, then run again.")


def _fetch_feed(api_base, token):
    url = api_base.rstrip("/") + "/api/merchant/verify-feed"
    req = urllib.request.Request(url, headers={"X-Verify-Token": token})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


# ── Chain sources for payment confirmation ─────────────────────────────────
# Two independent ways to check whether an address ACTUALLY received its funds,
# so the "paid" the server reports is reconciled against the chain itself:
#   esplora  an Esplora HTTP API (mempool.space, blockstream.info, or your own
#            self-hosted mempool/Esplora instance).
#   electrum your own Electrum server (Fulcrum / electrs), queried directly.
# Either way the money can only be in your own wallet, so this catches a false
# "paid" (server claims it, chain has no funds) and a payment the server missed.

_B32C = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def _scripthash(address):
    """Electrum scripthash for a bech32 (P2WPKH) address: sha256 of the
    scriptPubKey, byte-reversed, hex. scriptPubKey = OP_0 PUSH20 <program>."""
    a = address.strip().lower()
    pos = a.rfind("1")
    data = [_B32C.find(c) for c in a[pos + 1:]]
    if any(x < 0 for x in data):
        raise ValueError("not a bech32 address")
    program = bytes(_convertbits(data[1:-6], 5, 8, False))  # drop witver + 6-char checksum
    spk = b"\x00" + bytes([len(program)]) + program
    return hashlib.sha256(spk).digest()[::-1].hex()

def _esplora_balance(base, address):
    url = base.rstrip("/") + "/api/address/" + address
    with urllib.request.urlopen(url, timeout=20) as r:
        d = json.loads(r.read().decode())
    conf = (d.get("chain_stats") or {}).get("funded_txo_sum", 0)
    mem  = (d.get("mempool_stats") or {}).get("funded_txo_sum", 0)
    return int(conf), int(mem)

def _electrum_balance(host, port, use_ssl, scripthash, timeout=20):
    import socket, ssl as _ssl
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        if use_ssl:
            # Self-hosted Electrum servers commonly use a self-signed cert, which
            # standard Electrum clients accept. This is your own node, so we do
            # not fail on that.
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        req = json.dumps({"id": 1, "method": "blockchain.scripthash.get_balance",
                          "params": [scripthash]}) + "\n"
        s.sendall(req.encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    resp = json.loads(buf.decode().strip())
    if resp.get("error"):
        raise ValueError(str(resp["error"]))
    r = resp.get("result") or {}
    return int(r.get("confirmed", 0)), int(r.get("unconfirmed", 0))

def _chain_received(cfg, address):
    """Return (confirmed_sats, unconfirmed_sats) for an address via the chosen
    source. Raises on any source error."""
    if cfg.get("source") == "electrum":
        if not cfg.get("electrum_host"):
            raise ValueError("electrum source selected but no electrum_host set")
        return _electrum_balance(cfg["electrum_host"], cfg.get("electrum_port", 50002),
                                 bool(cfg.get("electrum_ssl", True)), _scripthash(address))
    return _esplora_balance(cfg.get("esplora_url") or "https://mempool.space", address)

def reconcile(cfg, feed):
    """Compare what the chain shows against what the server reports for every
    paid or pending invoice. Returns (ok, notes, dangers, findings[])."""
    relevant = [i for i in feed.get("invoices", [])
                if i.get("status") in ("paid", "paid_late", "pending")]
    ok = notes = dangers = 0
    findings = []
    for inv in relevant:
        addr = inv.get("address"); expected = int(inv.get("amount_sats") or 0)
        try:
            conf, unconf = _chain_received(cfg, addr)
        except Exception as e:
            findings.append(("danger", inv, f"chain source error: {e}")); dangers += 1; continue
        # Cross-check against a second, independent explorer if configured, so one
        # dishonest or lagging source cannot mislead you on its own.
        xurl = cfg.get("xcheck_url")
        if xurl:
            try:
                c2, _ = _esplora_balance(xurl, addr)
                if c2 != conf:
                    findings.append(("note", inv,
                        f"explorers disagree: primary={conf}, {xurl}={c2} sats; re-check or use your own node"))
                    notes += 1
                    continue
            except Exception as e:
                findings.append(("note", inv, f"cross-check source error: {e}")); notes += 1
        server_paid = inv.get("status") in ("paid", "paid_late")
        chain_paid  = expected > 0 and conf >= expected
        chain_seen  = expected > 0 and (conf + unconf) >= expected
        if server_paid and chain_paid:
            ok += 1
        elif server_paid and not chain_paid:
            findings.append(("danger", inv,
                f"server says PAID but chain shows {conf} of {expected} sats confirmed")); dangers += 1
        elif not server_paid and chain_paid:
            findings.append(("note", inv, f"PAID on chain, server still shows {inv.get('status')}")); notes += 1
        elif not server_paid and chain_seen:
            findings.append(("note", inv, "unconfirmed payment seen, awaiting confirmation")); notes += 1
        else:
            ok += 1
    return ok, notes, dangers, findings


def _prep_keys(cfg):
    """Return the list of zpubs to check against: your current one plus any
    previous ones you rotated away from. Every key is sanity-checked."""
    def norm(z):
        z = derive.extract_zpub(z)
        return z if z.lower().startswith("zpub") else ""
    cur = norm(cfg["zpub"])
    if not cur:
        raise ValueError("No valid zpub configured (it must start with 'zpub').")
    keys = [cur] + [k for k in (norm(z) for z in (cfg.get("previous_zpubs") or [])) if k]
    for k in keys:
        derive.derive_address(k, 0)  # sanity-check every key up front
    return keys


def verify_once(cfg):
    """Check every invoice address against a key YOU control.

    Returns (checked, unverified[list], mismatches[list]).

    Security: we never let the server's wallet tag (`zpub_hash`) decide what to
    skip, because the server controls that field. An address that does not
    derive from any key you gave us is always surfaced, so a compromised server
    cannot hide a substituted address by mislabelling which wallet it belongs to:
      - tagged as your current wallet but does not derive  -> hard mismatch
      - tagged as a wallet you did not provide             -> unverified (shown)
    Provide previous zpubs (rotations) so legitimate old invoices verify cleanly
    and only genuinely unexplained addresses remain in `unverified`.
    """
    if not cfg["verify_token"]:
        raise ValueError("No verification token configured.")
    keys = _prep_keys(cfg)
    hashes = {hashlib.sha256(k.encode()).hexdigest() for k in keys}

    feed = _fetch_feed(cfg["api_base"], cfg["verify_token"])
    invoices = feed.get("invoices", [])

    checked, unverified, mismatches = 0, [], []
    for inv in invoices:
        addr = inv.get("address"); idx = inv.get("index")
        matched = False
        for k in keys:
            try:
                if derive.derive_address(k, int(idx)) == addr:
                    matched = True
                    break
            except Exception:
                pass
        if matched:
            checked += 1
            continue
        ih = inv.get("zpub_hash") or ""
        if ih and ih not in hashes:
            # Tagged as a wallet you did not provide: a legitimate old wallet, or
            # a server trying to hide a substitution behind a fake tag. Surfaced.
            unverified.append((inv.get("id", "?"), idx, addr))
        else:
            mismatches.append((inv.get("id", "?"), idx, addr, "does not derive from your key"))
    return checked, unverified, mismatches


def _run(cfg):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    checked, unverified, mismatches = verify_once(cfg)
    rc = 0
    if mismatches:
        print(f"[{stamp}] ALARM: {len(mismatches)} address(es) do NOT derive from your key.")
        for iid, idx, addr, why in mismatches:
            print(f"    invoice {iid} (m/0/{idx}): server said {addr} ; {why}")
        print("    Do not trust these invoices. Stop sharing new links and contact support.")
        rc = 1
    else:
        print(f"[{stamp}] OK: {checked} address(es) verified against your key.")
    if unverified:
        print(f"[{stamp}] NOTE: {len(unverified)} invoice(s) could not be verified against your key, "
              f"tagged as another wallet.")
        for iid, idx, addr in unverified[:20]:
            print(f"    invoice {iid} (index {idx}): {addr}")
        print("    If you rotated your wallet, add the previous zpub(s) with --prev-zpub to check these.")
        print("    If you did NOT rotate, treat these as suspicious: a server cannot hide a substituted")
        print("    address from you, only mislabel it, and this is that label.")

    # Optional: reconcile on-chain payments against what the server reports.
    if cfg.get("confirm"):
        try:
            feed = _fetch_feed(cfg["api_base"], cfg["verify_token"])
            okc, notes, dangers, findings = reconcile(cfg, feed)
        except Exception as e:
            print(f"[warn] payment reconciliation failed: {e}")
            return rc
        src = ("your Electrum server" if cfg.get("source") == "electrum"
               else (cfg.get("esplora_url") or "mempool.space"))
        if dangers:
            print(f"[{stamp}] PAYMENT ALARM: {dangers} discrepancy(ies) vs {src}.")
            for sev, inv, why in findings:
                if sev == "danger":
                    print(f"    invoice {inv.get('id')} ({inv.get('address')}): {why}")
            print("    Do not fulfil an order the server calls paid until the funds are in your own wallet.")
            rc = 1
        else:
            print(f"[{stamp}] PAYMENTS OK: {okc} reconciled vs {src}"
                  + (f", {notes} informational." if notes else "."))
        for sev, inv, why in findings:
            if sev == "note":
                print(f"    note: invoice {inv.get('id')} ({inv.get('address')}): {why}")
    return rc


def main():
    ap = argparse.ArgumentParser(description="Independent BoreLine invoice-address verifier.")
    ap.add_argument("--watch", type=int, metavar="SECONDS",
                    help="re-check on a loop every SECONDS instead of once")
    ap.add_argument("--zpub", help="override the configured zpub")
    ap.add_argument("--prev-zpub", action="append", metavar="ZPUB",
                    help="a previous zpub you rotated away from, repeatable, so old invoices verify")
    ap.add_argument("--token", help="override the configured verification token")
    ap.add_argument("--api", help="override the API base URL")
    ap.add_argument("--confirm", action="store_true",
                    help="also reconcile on-chain payments against the server's reported status")
    ap.add_argument("--source", choices=["esplora", "electrum"],
                    help="chain source for --confirm (default esplora)")
    ap.add_argument("--esplora-url",
                    help="Esplora API base for --confirm (default https://mempool.space; or your own instance)")
    ap.add_argument("--electrum-host", help="your Electrum server host (Fulcrum / electrs) for --confirm")
    ap.add_argument("--electrum-port", type=int, help="Electrum server port (default 50002)")
    ap.add_argument("--electrum-no-ssl", action="store_true",
                    help="connect to the Electrum server without TLS")
    ap.add_argument("--xcheck", action="store_true",
                    help="cross-check payments against a second explorer (blockstream.info) and flag disagreements")
    ap.add_argument("--xcheck-url", help="a specific second Esplora API to cross-check against")
    args = ap.parse_args()

    cfg = _load_config()
    if args.zpub:  cfg["zpub"] = args.zpub
    if args.prev_zpub: cfg["previous_zpubs"] = (cfg.get("previous_zpubs") or []) + args.prev_zpub
    if args.token: cfg["verify_token"] = args.token
    if args.api:   cfg["api_base"] = args.api
    if args.confirm: cfg["confirm"] = True
    if args.source: cfg["source"] = args.source
    if args.esplora_url: cfg["esplora_url"] = args.esplora_url
    if args.electrum_host:
        cfg["electrum_host"] = args.electrum_host
        if not args.source: cfg["source"] = "electrum"
    if args.electrum_port: cfg["electrum_port"] = args.electrum_port
    if args.electrum_no_ssl: cfg["electrum_ssl"] = False
    if args.xcheck_url: cfg["xcheck_url"] = args.xcheck_url
    elif args.xcheck: cfg["xcheck_url"] = "https://blockstream.info"

    if not cfg["zpub"] or cfg["zpub"].startswith("zpub...") or not cfg["verify_token"]:
        if not os.path.exists(CONFIG_FILE):
            _write_config_template()
        else:
            print("Fill in your zpub and verification token in verifier_config.json (or pass --zpub/--token).")
        return 2

    if args.watch:
        print(f"Watching every {args.watch}s. Ctrl+C to stop.")
        last_bad = False
        try:
            while True:
                try:
                    rc = _run(cfg)
                    last_bad = rc == 1
                except Exception as e:
                    print(f"[warn] check failed: {e}")
                time.sleep(max(15, args.watch))
        except KeyboardInterrupt:
            return 1 if last_bad else 0
    else:
        try:
            return _run(cfg)
        except Exception as e:
            print(f"[error] {e}")
            return 2


if __name__ == "__main__":
    sys.exit(main())
