# Verifiable core

This is the part of BoreLine you do not have to take on faith.

`derive.py` is the exact logic BoreLine uses to turn your **ZPUB** into receiving addresses, extracted as a standalone, dependency-free Python module. It is the code that backs the whole "verify, do not trust" promise. Run it, read it, and confirm for yourself that:

1. Every invoice address is a **standard BIP84 address derived from your own public key**, so payments can only ever land in a wallet you control.
2. The **ZPUB fingerprint** shown on your dashboard is just a SHA-256 hash of your public key, nothing that could move funds.

## What this code is, and is not

- **It is** pure BIP32 / BIP84 / bech32 math, Python 3 standard library only, no `pip install`, no network calls.
- **It operates on a public key** (a watch-only ZPUB) that you provide. A ZPUB can generate addresses but can **never** spend.
- **It contains no secrets**: no private keys, no seed, no API keys, no database, no server configuration. There is nothing here that could give anyone access to anything.

## Try it

Derive the first receiving addresses and the fingerprint for a ZPUB:

```bash
python derive.py <your-zpub> 5
```

Check whether a specific address belongs to a ZPUB:

```bash
python derive.py <your-zpub> --check bc1q...
```

## Prove it is correct

Run the self-test. It checks the code against the official BIP84 specification vector (the index 1 address is the exact value published in BIP84):

```bash
python test_vectors.py
```

Expected output:

```
[ok] m/0/0  bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
[ok] m/0/1  bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g
[ok] m/0/2  bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z
[ok] fingerprint  e06675e6ba2f9dddf8e87123bb2d426b1b2b663382d500e47e4f1126996fd074
[ok] address_belongs_to_zpub -> index 2

ALL PASSED
```

## The three-way check that proves non-custody

For your own ZPUB, run `derive.py` and line up **three independent sources**:

1. The addresses this script prints.
2. The addresses your own wallet shows (Sparrow, Electrum, BlueWallet, any BIP84 tool).
3. The addresses on BoreLine's **Verify** page in your dashboard.

If all three match, you have proven, without trusting BoreLine, that invoices pay out to addresses only your wallet controls. BoreLine derives them the same way this script does, and cannot reroute them, because it never holds the private keys.

## Derivation details

- Path: the ZPUB is the account key `m/84'/0'/0'`. Receiving addresses are `m/0/index`.
- Output: native SegWit `bc1q...` (P2WPKH), per BIP84.
- Fingerprint: `SHA-256(zpub)`, hex encoded.

## Automatic verification: check every invoice, not a sample

Reading addresses by hand does not scale. A merchant cannot eyeball every invoice against their wallet, and "verify a few and trust the rest" is exactly the gap a dishonest host would exploit. So the same derivation runs as a verifier that checks **every** invoice address against your own key, on your own machine. It re-derives `m/0/index` for each of your invoices and confirms it matches the address the server issued. Your key comes from you and this code comes from this repo, so a compromised server cannot pass the check by handing over a matching fake: it never supplies the key the check runs against.

There are two forms, same logic. Pick whichever fits you.

### 1. `verify.html` — one file, no install

Download `verify.html`, open it in your browser (it works straight from disk), and paste three things once: your **zpub**, a **verification token**, and the API base (defaults to `https://api.borelinepay.uk`). Press **Verify now**. It fetches your invoice list, re-derives every address, and shows all-clear or flags any mismatch. Tick "remember on this device" to store the values locally so you never retype them. All maths runs in your browser; your key is never sent anywhere.

For an air-gapped setup, fetch the feed on another machine and paste the JSON into the tool's offline mode.

### 2. `verify_invoices.py` — script, for automation and alerts

For a headless check you can schedule:

```bash
python verify_invoices.py            # one check
python verify_invoices.py --watch 300  # re-check every 300 seconds
```

On first run it writes `verifier_config.json`; fill in your `zpub` and `verify_token` (or pass `--zpub`/`--token`, or set `BORELINE_ZPUB`/`BORELINE_VERIFY_TOKEN`). It exits `0` when every address matched your key and `1` on any mismatch, so you can wire it into cron and an alert. Standard library only, plus the `derive.py` next to it.

### After a wallet rotation, and why nothing is silently skipped

The verifier checks every invoice address against a key **you** hold, and never uses the server's wallet label to decide what to skip, because the server controls that label. An address that derives from none of your keys is always surfaced: as a hard **mismatch** if it is tagged as your current wallet, or as **unverified** if it is tagged as a wallet you did not provide. So a compromised server cannot hide a substituted address by mislabelling which wallet it belongs to. The worst it can do is push it into the "unverified" list, where you still see it and can investigate.

If you have rotated your ZPUB, give the verifier your previous key(s) so legitimate old invoices verify cleanly: paste them in the "previous zpub(s)" box in `verify.html`, or pass `--prev-zpub` (repeatable) to the script. Anything still unverified after that, when you have not rotated, should be treated as suspicious.

### Report a mismatch and freeze the account

Finding a mismatch is not the end of it: you can report it back and have BoreLine **stop the account immediately**. In `verify.html` a "Report to BoreLine and freeze this account" button appears whenever an address is flagged; in the script, add `--report` (pair it with `--watch` for unattended monitoring). A report is authenticated by your verification token, so it can only ever freeze **your own** account.

On a report the server re-derives the address from the key it holds and decides:

- **Corroborated** — the server's own re-derivation disagrees too. Unambiguous tampering.
- **Unconfirmed** — the server's data is self-consistent (often just a wrong zpub in the verifier). A precautionary hold is still placed, fail-safe.

A frozen account can create no new invoices and its hosted pay pages stop, so no customer can pay a flagged address while it is investigated. The BoreLine team is alerted and is the only party who can lift a hold, after review. The server also runs the same check on its own on a schedule, and if corroborated mismatches show up across several accounts at once it treats the failure as server-level and halts everyone, rather than assuming a single account. None of this can touch funds; it only pauses new payment requests.

### Confirm payments, not just addresses

Verifying the address proves funds can only land in your wallet. It does not prove a payment the server *reports* as received actually arrived, since that "paid" signal is the server's word. So both tools can also reconcile payments against the chain itself, using a source **you** choose:

- **A public explorer** or your **own self-hosted** Esplora / mempool instance (any Esplora-compatible HTTP API).
- **Your own Electrum server** (Fulcrum / electrs), queried directly, for people who run a bare node (script only).

For every paid or pending invoice it checks what the address actually received and compares it to what BoreLine reports. The important case it catches is a **"paid" we claim with no on-chain funds**: never fulfil that order. It also surfaces payments the chain shows that the server has not marked yet. In `verify.html` use the "Confirm payments on chain" panel; in the script add `--confirm` (and `--source electrum --electrum-host …` for your own node). The money is always in your own wallet, so the worst a dishonest server can do is misreport, and this is how you catch it.

**Cross-check two explorers.** So that a single dishonest or lagging explorer cannot mislead you either, you can check every address against **two** independent sources and flag any disagreement: put a second URL in the "cross-check source" box in `verify.html`, or pass `--xcheck` (uses blockstream.info) or `--xcheck-url <esplora>` to the script. Your own node remains the fully trustless option.

### Getting the verification token

Both tools read your own invoice list from a minimal, read-only endpoint (`/api/merchant/verify-feed`) that returns only each invoice's derivation index, the issued address, and which wallet it belongs to. Nothing else, no amounts or customer data. Authenticate it with a **verification token**: in your dashboard, open the **Verify** page and generate one. It is a dedicated, revocable credential that unlocks **only** this address feed, so it is separate from any paired phone and cannot read customer data, move funds, or change settings. Generate a new one any time to rotate it, or revoke it to cut off access. The token is stored only as a hash and shown once, so save it when you create it (or tick "remember on this device"); if you lose it, just generate a new one.

The check is deterministic: one zpub plus one index is exactly one address. If your key and the server's address ever disagree, the tool says so before you share the link.

## Prove the verifier itself has not been tampered with

A verifier is only worth running if you can trust the verifier. You do not have to take ours on faith. In order of how little trust each check requires:

1. **Self-test (needs no trust in BoreLine).** `verify.html` has a **Self-test** button, and `verify_invoices.py` shares its logic with `python test_vectors.py`. Both derive the published **BIP84 specification vector** (the standard "abandon abandon ... about" test key) and check it against the known addresses. That vector is defined by the Bitcoin spec, not by us. If the tool derives it correctly, its derivation is honest, whoever shipped the file. If a tampered build faked addresses, the self-test fails.
2. **Air-gap test (proves it sends nothing).** Turn off your network and run the verifier in offline mode (paste a feed). It still works, because every calculation is local. A tool that needed to phone home to function could not do this. You can also open your browser's developer tools, Network tab, run a live check, and confirm the only request is to your own API base and that your zpub never appears in it.
3. **Read it.** These files are small, unminified, dependency-free, and load no external scripts, fonts, or images. `verify.html` makes exactly one network call, to the API base you enter. You, or anyone, can read the whole thing.
4. **Checksums (catches tampering in transit).** `CHECKSUMS.txt` lists the SHA-256 of each file. Confirm your download matches. Note the honest limit: a matching checksum proves the file was not altered after we published it, but not that we published an honest file. That is what checks 1 and 2 are for, since they do not require trusting us at all.
5. **Commit and tag provenance (catches a stolen account).** Every change here is in public git history, so you can see exactly what changed and when. Where a release tag is GPG-signed, verifying that signature proves the files came from the holder of BoreLine's key and were not swapped by a third party who compromised the hosting.

The design goal is that the two checks that matter most, correctness and confidentiality, are provable **without trusting BoreLine**: the spec vector is external, and "run it offline" is something you control.
