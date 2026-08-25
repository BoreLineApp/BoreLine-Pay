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
