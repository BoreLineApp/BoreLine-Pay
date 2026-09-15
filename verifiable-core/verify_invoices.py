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
import urllib.parse
import urllib.request

import derive  # the sibling module in verifiable-core/

DEFAULT_API = "https://api.borelinepay.uk"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifier_config.json")

# Some hosts (Cloudflare in front of the API, and public explorers like
# mempool.space) reject the default Python-urllib user agent with 403 Forbidden.
# Identify ourselves with a normal user agent so plain HTTPS requests are served.
_UA = "Mozilla/5.0 (compatible; BoreLineVerifier/1.0; +https://boreline.app)"

def _open(url, data=None, headers=None, method=None, timeout=30):
    """urllib.request.urlopen with our user agent always set. Accepts a URL string
    or an existing Request. Returns the response context manager."""
    if isinstance(url, urllib.request.Request):
        req = url
        req.add_header("User-Agent", _UA)
    else:
        h = {"User-Agent": _UA}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=data, headers=h, method=method)
    return urllib.request.urlopen(req, timeout=timeout)


def _load_config():
    """Merge, in order of precedence: CLI flags > env vars > verifier_config.json."""
    cfg = {"api_base": DEFAULT_API, "zpub": "", "verify_token": "", "previous_zpubs": [],
           "source": "esplora", "esplora_url": "https://mempool.space", "xcheck_url": "",
           "electrum_host": "", "electrum_port": 50002, "electrum_ssl": True,
           "telegram_bot_token": "", "telegram_chat_id": ""}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg.update({k: v for k, v in json.load(f).items() if v})
        except Exception as e:
            print(f"[warn] could not read {CONFIG_FILE}: {e}")
    cfg["api_base"] = os.environ.get("BORELINE_API", cfg["api_base"])
    cfg["zpub"] = os.environ.get("BORELINE_ZPUB", cfg["zpub"])
    cfg["verify_token"] = os.environ.get("BORELINE_VERIFY_TOKEN", cfg["verify_token"])
    cfg["telegram_bot_token"] = os.environ.get("BORELINE_TG_BOT_TOKEN", cfg["telegram_bot_token"])
    cfg["telegram_chat_id"] = os.environ.get("BORELINE_TG_CHAT_ID", cfg["telegram_chat_id"])
    return cfg


def _write_config_template():
    tmpl = {"api_base": DEFAULT_API, "zpub": "zpub...paste yours here...",
            "verify_token": "generate this on your dashboard Verify page"}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(tmpl, f, indent=2)
    print(f"Wrote a template to {CONFIG_FILE}. Fill in your zpub and verification token, then run again.")


def _fetch_feed(api_base, token):
    url = api_base.rstrip("/") + "/api/merchant/verify-feed"
    with _open(url, headers={"X-Verify-Token": token}, timeout=30) as r:
        return json.loads(r.read().decode())


def _post_report(api_base, token, inv_id, index, address):
    """Report a derivation mismatch to the server, which freezes THIS account
    (new invoices and hosted pay pages stop) and alerts the BoreLine team. The
    server independently re-derives to mark it corroborated or unconfirmed.
    Returns the server's response dict, or raises."""
    url  = api_base.rstrip("/") + "/api/merchant/verify-report"
    body = json.dumps({"invoice_id": inv_id, "index": index, "address": address}).encode()
    with _open(url, data=body, method="POST",
               headers={"X-Verify-Token": token, "Content-Type": "application/json"},
               timeout=30) as r:
        return json.loads(r.read().decode())


# ── Phone alerts via your own Telegram bot ─────────────────────────────────
# Optional. The Telegram Bot API is plain HTTPS, so this stays standard library
# only. You create the bot with @BotFather, paste its token and your chat id,
# and the verifier messages your phone the moment a check fails. It is YOUR bot,
# talking to YOUR chat: BoreLine is not involved and sees none of it.
_TG_ALERTED = set()  # de-dupe repeat alerts for the same problem within a run

def _tg_send(cfg, text):
    """Send a Telegram message via the merchant's own bot. Returns True on success,
    False if not configured or on error."""
    tok = (cfg.get("telegram_bot_token") or "").strip()
    chat = (cfg.get("telegram_chat_id") or "").strip()
    if not tok or not chat:
        return False
    url = f"https://api.telegram.org/bot{tok}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat, "text": text,
                                   "disable_web_page_preview": "true"}).encode()
    try:
        with _open(url, data=data, timeout=15) as r:
            return getattr(r, "status", 200) == 200
    except Exception as e:
        print(f"[warn] Telegram notify failed: {e}")
        return False

def _tg_alert(cfg, key, text):
    """Send an alert once per distinct problem within this run, so a persistent
    issue does not re-message you every watch cycle."""
    if key in _TG_ALERTED:
        return
    if _tg_send(cfg, text):
        _TG_ALERTED.add(key)


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

def _addr_url_seg(address):
    """Return a URL-safe path segment for an address that came from the server.
    The server is exactly what this tool audits, so its address string is
    untrusted: percent-encode it so a crafted value cannot inject extra path
    segments, a query string, or newlines into the explorer request. A valid
    bech32 address is all unreserved characters, so this is a no-op for honest
    data and only neutralises malicious input."""
    return urllib.parse.quote(str(address or ""), safe="")

def _esplora_balance(base, address):
    url = base.rstrip("/") + "/api/address/" + _addr_url_seg(address)
    with _open(url, timeout=20) as r:
        d = json.loads(r.read().decode())
    conf = (d.get("chain_stats") or {}).get("funded_txo_sum", 0)
    mem  = (d.get("mempool_stats") or {}).get("funded_txo_sum", 0)
    return int(conf), int(mem)

def _electrum_balance(host, port, use_ssl, scripthash, timeout=20, insecure=False):
    import socket, ssl as _ssl
    s = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        if use_ssl:
            ctx = _ssl.create_default_context()
            if insecure:
                # Opt-in only: accept a self-signed certificate on a node YOU
                # control. Standard Electrum servers commonly use one, but this
                # disables MITM protection on the link, so it is off by default
                # and never assumed for you.
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s, server_hostname=host)
            except _ssl.SSLCertVerificationError:
                raise ValueError(
                    "Electrum server certificate could not be verified. If this is "
                    "your own self-signed node, set \"electrum_ssl_insecure\": true "
                    "in verifier_config.json to accept it.")
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
                                 bool(cfg.get("electrum_ssl", True)), _scripthash(address),
                                 insecure=bool(cfg.get("electrum_ssl_insecure", False)))
    return _esplora_balance(cfg.get("esplora_url") or "https://mempool.space", address)

def _min_ts_for_inv(inv):
    """Unix timestamp before which on-chain history is ignored (invoice creation
    minus a 1 hour skew), matching the server. None if there is no creation time,
    in which case reconciliation cannot exclude a reused address's prior funds."""
    c = inv.get("created_at")
    if not c:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(c)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp()) - 3600
    except Exception:
        return None

def _esplora_received_since(base, address, min_ts, need):
    """Sats an address received, counting only transactions at or after min_ts
    (None = count all, cannot time-filter). Uses the tx list, not the lifetime
    address total, so funds that predate the invoice are excluded. Returns
    (confirmed, mempool, conf_paid, mem_paid) where *_paid means a single
    qualifying tx sent at least `need`, matching the server's rule."""
    url = base.rstrip("/") + "/api/address/" + _addr_url_seg(address) + "/txs"
    with _open(url, timeout=20) as r:
        txs = json.loads(r.read().decode())
    confirmed = mempool = 0
    conf_paid = mem_paid = False
    for tx in (txs or []):
        st = tx.get("status", {}) or {}
        if st.get("confirmed") and min_ts is not None and st.get("block_time") is not None \
                and st["block_time"] < min_ts:
            continue
        recv = sum(int(v.get("value", 0)) for v in (tx.get("vout") or [])
                   if v.get("scriptpubkey_address") == address)
        if st.get("confirmed"):
            confirmed += recv
            if recv >= need:
                conf_paid = True
        else:
            mempool += recv
            if recv >= need:
                mem_paid = True
    return confirmed, mempool, conf_paid, mem_paid

def _chain_received_since(cfg, address, min_ts, need):
    """Payment view for reconciliation. Returns
    (confirmed, mempool, conf_paid, mem_paid, filtered). For Esplora it is time
    filtered by min_ts. For Electrum it falls back to the current balance, which
    cannot exclude prior history, so filtered is False and callers add a caveat."""
    if cfg.get("source") == "electrum":
        conf, unconf = _chain_received(cfg, address)
        return conf, unconf, conf >= need, (conf + unconf) >= need, False
    base = cfg.get("esplora_url") or "https://mempool.space"
    c, m, cp, mp = _esplora_received_since(base, address, min_ts, need)
    return c, m, cp, mp, (min_ts is not None)

def reconcile(cfg, feed):
    """Compare what the chain shows against what the server reports for every
    paid or pending invoice. Returns (ok, notes, dangers, findings[]).

    Ownership first: every address is re-derived from YOUR key before it is
    reconciled. Checking a server-supplied address against the chain proves
    nothing on its own, a substituted address the server controls would show as
    'paid' too. So an address that does not derive from a key you provided is
    flagged, never quietly reconciled."""
    keys = _prep_keys(cfg)  # validates your zpub(s); raises if none is valid
    key_hashes = {hashlib.sha256(k.encode()).hexdigest() for k in keys}

    def _mine(inv):
        try:
            idx = int(inv.get("index"))
        except (TypeError, ValueError):
            return False
        for k in keys:
            try:
                if derive.derive_address(k, idx) == inv.get("address"):
                    return True
            except Exception:
                pass
        return False

    relevant = [i for i in feed.get("invoices", [])
                if i.get("status") in ("paid", "paid_late", "pending")]
    ok = notes = dangers = 0
    findings = []
    for inv in relevant:
        addr = inv.get("address"); expected = int(inv.get("amount_sats") or 0)
        min_ts = _min_ts_for_inv(inv)
        try:
            conf, mem, conf_paid, mem_paid, filtered = _chain_received_since(cfg, addr, min_ts, expected)
        except Exception as e:
            findings.append(("danger", inv, f"chain source error: {e}")); dangers += 1; continue
        # OWNERSHIP: does this address derive from a key you gave us? If not,
        # reconciling it is meaningless, a payment there does not reach you.
        if not _mine(inv):
            got = conf + mem
            ih = inv.get("zpub_hash") or ""
            if ih and ih not in key_hashes:
                findings.append(("note", inv,
                    "not verified: derives from a wallet you did not provide"
                    + (f", received {got} sats" if got else "")
                    + ". If you rotated, add the previous zpub with --prev-zpub."))
                notes += 1
            else:
                findings.append(("danger", inv,
                    "NOT YOUR ADDRESS: does not derive from your key"
                    + (f", yet it received {got} sats" if got else "")
                    + ". A payment here does not reach you."))
                dangers += 1
            continue
        # Cross-check against a second, independent explorer if configured, so one
        # dishonest or lagging source cannot mislead you on its own.
        xurl = cfg.get("xcheck_url")
        if xurl:
            try:
                c2, _, _, _ = _esplora_received_since(xurl, addr, min_ts, expected)
                if c2 != conf:
                    findings.append(("note", inv,
                        f"explorers disagree: primary={conf}, {xurl}={c2} sats; re-check or use your own node"))
                    notes += 1
                    continue
            except Exception as e:
                findings.append(("note", inv, f"cross-check source error: {e}")); notes += 1
        server_paid = inv.get("status") in ("paid", "paid_late")
        # Paid = a confirmed tx of at least the amount, received at or after the
        # invoice was created (matches the server); prior history is excluded.
        caveat = "" if filtered else (" (lifetime balance, no creation time, may "
                                      "include funds that predate the invoice)")
        if server_paid and conf_paid:
            ok += 1
        elif server_paid and not conf_paid:
            findings.append(("danger", inv,
                f"server says PAID but the chain shows no confirmed payment of "
                f"{expected} sats since the invoice was created (found {conf})")); dangers += 1
        elif not server_paid and conf_paid:
            findings.append(("note", inv, f"PAID on chain, server still shows {inv.get('status')}{caveat}")); notes += 1
        elif not server_paid and mem_paid:
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
        _tg_alert(cfg, "mismatch:" + ",".join(sorted(str(m[0]) for m in mismatches)),
                  "\U0001F6A8 BoreLine verifier ALARM\n\n"
                  f"{len(mismatches)} invoice address(es) do NOT derive from your key. "
                  "Funds sent to these could be redirected. Do not trust these invoices and contact support.\n"
                  "Invoices: " + ", ".join(str(m[0]) for m in mismatches[:10]))
        # Optional: report the first mismatch, which freezes this account on the
        # server (no new invoices, hosted pay pages disabled) and alerts BoreLine.
        # Meant for unattended --watch monitoring so a breach is contained even
        # when nobody is looking.
        if cfg.get("report"):
            iid, idx, addr, _why = mismatches[0]
            try:
                d = _post_report(cfg["api_base"], cfg["verify_token"], iid, idx, addr)
                print(f"[{stamp}] REPORTED to BoreLine: account halted "
                      f"(verdict: {d.get('kind','?')}). Payments are stopped on this "
                      f"account until the BoreLine team clears it.")
            except Exception as e:
                print(f"[{stamp}] [warn] could not send mismatch report: {e}")
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
            dids = sorted(str(inv.get("id", "?")) for sev, inv, _ in findings if sev == "danger")
            _tg_alert(cfg, "payment:" + ",".join(dids),
                      "⚠ BoreLine verifier: payment reconciliation\n\n"
                      f"{dangers} discrepancy(ies) against {src}. An address that is not yours, or a "
                      "'paid' the chain does not back. Do not fulfil those orders until funds are in "
                      "your own wallet.\nInvoices: " + ", ".join(dids[:10]))
        else:
            print(f"[{stamp}] PAYMENTS OK: {okc} reconciled vs {src}"
                  + (f", {notes} informational." if notes else "."))
        for sev, inv, why in findings:
            if sev == "note":
                print(f"    note: invoice {inv.get('id')} ({inv.get('address')}): {why}")
    return rc


# ── Interactive menu ───────────────────────────────────────────────────────
# A click-to-start, single-key menu so a merchant never has to remember flags.
# Standard library only, so the whole tool stays dependency free and auditable.

def _getch():
    """Read one keypress without waiting for Enter, cross-platform. Falls back to
    a line read if there is no real terminal (a pipe or redirect), so it never
    blocks waiting on a console that is not there."""
    def _line_or_quit():
        # Empty string from readline means EOF (a closed pipe / no input): quit
        # rather than loop forever redrawing the menu.
        line = sys.stdin.readline()
        if line == "":
            return "q"
        return (line.strip() or " ")[:1]
    try:
        if not sys.stdin.isatty():
            return _line_or_quit()
    except Exception:
        pass
    try:
        import msvcrt  # Windows
        return msvcrt.getwch()
    except ImportError:
        pass
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        return ch
    except Exception:
        return _line_or_quit()

def _pause():
    print("\n  Press any key to return to the menu...")
    _getch()

def _short(v):
    v = (v or "").strip()
    if not v or v.startswith("zpub..."):
        return "not set"
    return (v[:10] + "…") if len(v) > 12 else v

def _save_config_keys(cfg):
    """Merge the editable keys into verifier_config.json, preserving anything else."""
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    for k in ("api_base", "zpub", "previous_zpubs", "verify_token", "report",
              "esplora_url", "source", "telegram_bot_token", "telegram_chat_id"):
        if k in cfg:
            data[k] = cfg[k]
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _setup_wizard(cfg):
    print("\n  Enter your details. Press Enter alone to keep the current value.\n")
    z = input(f"  Your zpub [{_short(cfg.get('zpub'))}]: ").strip()
    if z:
        cfg["zpub"] = z
    p = input("  Previous zpub(s) after a rotation, comma separated, Enter to skip: ").strip()
    if p:
        cfg["previous_zpubs"] = [x.strip() for x in p.split(",") if x.strip()]
    t = input(f"  Verification token [{_short(cfg.get('verify_token'))}]: ").strip()
    if t:
        cfg["verify_token"] = t
    a = input(f"  API base [{cfg.get('api_base') or DEFAULT_API}]: ").strip()
    if a:
        cfg["api_base"] = a
    print("\n  Phone alerts (optional). Create a bot with @BotFather on Telegram,")
    print("  send it a message, then get your chat id from @userinfobot. Enter to skip.")
    bt = input(f"  Telegram bot token [{_short(cfg.get('telegram_bot_token'))}]: ").strip()
    if bt:
        cfg["telegram_bot_token"] = bt
    ci = input(f"  Telegram chat id [{_short(cfg.get('telegram_chat_id'))}]: ").strip()
    if ci:
        cfg["telegram_chat_id"] = ci
    _save_config_keys(cfg)
    print(f"\n  Saved to {CONFIG_FILE}")
    if cfg.get("telegram_bot_token") and cfg.get("telegram_chat_id"):
        if _tg_send(cfg, "BoreLine verifier: phone alerts are set up. You will be messaged here if a check ever fails."):
            print("  Sent a test message to your Telegram. Check your phone.")
        else:
            print("  Could not send a test message. Double-check the bot token and chat id.")
    _pause()

def _is_windows():
    return os.name == "nt" or sys.platform.startswith("win")

def _startup_bat_path():
    """Path to the auto-start launcher in the current user's Windows Startup
    folder. Files there run automatically at login, in a visible window, with no
    admin rights needed. None if the folder cannot be located."""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return None
    return os.path.join(appdata, "Microsoft", "Windows", "Start Menu",
                        "Programs", "Startup", "BoreLine-Verifier.bat")

def _autostart_enabled():
    if _is_windows():
        p = _startup_bat_path()
        return bool(p and os.path.exists(p))
    return False

def _enable_autostart(interval):
    """Create the Startup launcher so the verifier opens in a visible window and
    starts watching every time the user logs in. Returns (ok, info)."""
    if not _is_windows():
        return False, "non-windows"
    p = _startup_bat_path()
    if not p:
        return False, "could not locate the Windows Startup folder"
    folder = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(folder, "verify_invoices.py")
    content = ("@echo off\r\n"
               "title BoreLine Verifier\r\n"
               f'cd /d "{folder}"\r\n'
               f'python "{script}" --watch {int(interval)}\r\n'
               "echo.\r\n"
               "echo The verifier has stopped. Press a key to close this window.\r\n"
               "pause\r\n")
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return True, p
    except Exception as e:
        return False, str(e)

def _disable_autostart():
    if not _is_windows():
        return False, "non-windows"
    p = _startup_bat_path()
    try:
        if p and os.path.exists(p):
            os.remove(p)
        return True, p
    except Exception as e:
        return False, str(e)

def _erase_all():
    """Delete the saved config and remove the auto-start entry, back to a clean
    slate. Does not touch the BoreLine account or any funds. Returns a list of
    what was removed."""
    removed = []
    try:
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
            removed.append("saved settings (verifier_config.json)")
    except Exception as e:
        print("  [warn] could not delete config:", e)
    if _autostart_enabled():
        okd, _ = _disable_autostart()
        if okd:
            removed.append("auto start on reboot")
    _TG_ALERTED.clear()
    return removed

def _watch_loop(cfg, secs):
    """Run a check every `secs` seconds until Ctrl+C, then return to the menu."""
    print(f"  Watching every {secs}s. Press Ctrl+C to stop and return to the menu.\n")
    try:
        while True:
            try:
                _run(cfg)
            except Exception as e:
                print("  [warn]", e)
            time.sleep(secs)
    except KeyboardInterrupt:
        print("\n  Stopped watching.")

def _ask_interval(prompt="  Re-check every how many seconds [300]: ", default=300):
    raw = input(prompt).strip()
    try:
        return max(15, int(raw)) if raw else default
    except ValueError:
        return default

def _menu():
    """Single-key interactive loop. Returns an exit code."""
    while True:
        cfg = _load_config()
        configured = bool(cfg.get("zpub") and not cfg["zpub"].startswith("zpub...")
                          and cfg.get("verify_token"))
        report_on = bool(cfg.get("report"))
        tg_on = bool(cfg.get("telegram_bot_token") and cfg.get("telegram_chat_id"))
        auto_on = _autostart_enabled()
        print("\n" + "=" * 54)
        print("   BORELINE ADDRESS VERIFIER")
        print("=" * 54)
        print("   Keys : " + ("configured" if configured else "NOT SET — choose 4 first"))
        print("   API  : " + (cfg.get("api_base") or DEFAULT_API))
        print()
        print("   [1] Check my addresses now")
        print("   [2] Watch continuously (auto re-check)")
        print("   [3] Confirm payments on chain")
        print("   [4] Set up or edit my keys")
        print("   [5] Auto report and freeze on mismatch: " + ("ON" if report_on else "off"))
        print("   [6] Phone alerts (Telegram): " + ("ON, send a test" if tg_on else "off, set up in option 4"))
        if _is_windows():
            print("   [7] Start automatically on reboot (opens a window): " + ("ON" if auto_on else "off"))
        print("   [8] Erase all saved data and start clean")
        print("   [q] Quit")
        print()
        sys.stdout.write("   Press a key: ")
        sys.stdout.flush()
        k = (_getch() or "").lower()
        print(k if k.strip() else "")

        if k == "1":
            if not configured:
                print("\n  Set up your keys first (option 4)."); _pause(); continue
            try:
                _run(dict(cfg))
            except Exception as e:
                print("  Error:", e)
            _pause()
        elif k == "2":
            if not configured:
                print("\n  Set up your keys first (option 4)."); _pause(); continue
            secs = _ask_interval()
            # Offer to also set up reboot auto-start now, so you do not have to
            # stop the watch later just to reach option 7.
            if _is_windows() and not auto_on:
                ans = input("  Also start automatically after a reboot? [y/N]: ").strip().lower()
                if ans in ("y", "yes"):
                    oke, info = _enable_autostart(secs)
                    print("  Auto start on reboot is ON.\n" if oke
                          else f"  Could not enable auto start: {info}\n")
            _watch_loop(dict(cfg), secs)
            _pause()
        elif k == "3":
            if not configured:
                print("\n  Set up your keys first (option 4)."); _pause(); continue
            c3 = dict(cfg)
            c3["confirm"] = True
            src = input(f"\n  Chain source Esplora URL [{c3.get('esplora_url') or 'https://mempool.space'}]: ").strip()
            if src:
                c3["esplora_url"] = src
            try:
                _run(c3)
            except Exception as e:
                print("  Error:", e)
            _pause()
        elif k == "4":
            _setup_wizard(cfg)
        elif k == "5":
            cfg["report"] = not report_on
            _save_config_keys(cfg)
            print("\n  Auto report is now " + ("ON" if cfg["report"] else "off") + ".")
            if cfg["report"]:
                print("  A mismatch will report and FREEZE the account with no further prompt.")
                print("  A wrong zpub, or a previous zpub you have not added, will also trigger it.")
            _pause()
        elif k == "6":
            if tg_on:
                print("\n  Sending a test message to your Telegram...")
                if _tg_send(cfg, "BoreLine verifier: test alert. If you see this, phone alerts work."):
                    print("  Sent. Check your phone.")
                else:
                    print("  Could not send. Check the bot token and chat id in option 4.")
            else:
                print("\n  Phone alerts are not set up yet. Choose option 4 and enter your")
                print("  Telegram bot token and chat id.")
            _pause()
        elif k == "7" and _is_windows():
            if auto_on:
                okd, info = _disable_autostart()
                print("\n  Auto start on reboot is now OFF." if okd
                      else f"\n  Could not turn it off: {info}")
            elif not configured:
                print("\n  Set up your keys first (option 4), then enable auto start.")
            else:
                secs = _ask_interval("\n  After reboot, re-check every how many seconds [300]: ")
                oke, info = _enable_autostart(secs)
                if oke:
                    print("\n  Done. Next time you log in, a window opens by itself and the")
                    print("  verifier starts watching automatically. To stop it, close that")
                    print("  window; to turn this off, come back here and press 7.")
                    ans = input("\n  Start watching now as well? [y/N]: ").strip().lower()
                    if ans in ("y", "yes"):
                        _watch_loop(dict(cfg), secs)
                else:
                    print(f"\n  Could not enable auto start: {info}")
            _pause()
        elif k == "8":
            print("\n  This erases everything saved on THIS device: your zpub, verification")
            print("  token, previous zpubs, Telegram alert details and settings, and it turns")
            print("  off auto start. Your BoreLine account, your wallet and your funds are NOT")
            print("  affected, and your token stays valid (revoke it from your dashboard if you")
            print("  want to kill access).")
            c = input("\n  Type ERASE to confirm, or press Enter to cancel: ").strip()
            if c == "ERASE":
                removed = _erase_all()
                if removed:
                    print("\n  Removed: " + "; ".join(removed) + ".")
                print("  Clean slate. Choose option 4 to set up again whenever you like.")
            else:
                print("\n  Cancelled, nothing was deleted.")
            _pause()
        elif k in ("q", "\x03", "\x1b"):
            print("\n  Bye.")
            return 0
        # any other key just redraws the menu


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
    ap.add_argument("--report", action="store_true",
                    help="on a mismatch, report it to BoreLine, which FREEZES this account "
                         "(no new invoices, hosted pay pages disabled) and alerts the team. "
                         "Use with --watch for unattended monitoring.")
    ap.add_argument("--menu", action="store_true",
                    help="open the interactive menu (no flags to remember). This is what the "
                         "double-click launchers use.")
    ap.add_argument("--telegram-bot-token",
                    help="your own Telegram bot token (from @BotFather) for phone alerts on a mismatch")
    ap.add_argument("--telegram-chat-id",
                    help="the Telegram chat id to message (from @userinfobot)")
    args = ap.parse_args()

    # Interactive menu: when asked for, or when double-clicked / run bare in a real
    # terminal. Never triggers under cron or a pipe (no TTY), so automation is unaffected.
    if args.menu or (len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty()):
        try:
            return _menu()
        except KeyboardInterrupt:
            print("\n  Bye.")
            return 0

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
    if args.report: cfg["report"] = True
    if args.telegram_bot_token: cfg["telegram_bot_token"] = args.telegram_bot_token
    if args.telegram_chat_id: cfg["telegram_chat_id"] = args.telegram_chat_id

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
