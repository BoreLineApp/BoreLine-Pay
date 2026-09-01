# Verify it yourself

BoreLine is built on one principle: **do not trust, verify.** You should not have to take the "we cannot touch your funds" claim on faith. Here is exactly how to prove it, independently, before you ever register a wallet that holds real money.

None of these steps require trusting BoreLine. They rely only on your own wallet and public, standard Bitcoin math.

## 1. Prove the addresses come from your key

The [`verifiable-core/`](../verifiable-core/) folder is the exact address-derivation logic BoreLine uses, as a standalone script you can read and run. Point it at your ZPUB:

```bash
cd verifiable-core
python derive.py <your-zpub> 5
```

It prints your first receiving addresses and the SHA-256 fingerprint of your key, with no network calls and no secrets involved.

Confirm the script itself is correct against the official BIP84 specification:

```bash
python test_vectors.py
```

## 2. Line up three independent sources

For your own ZPUB, compare the addresses from **three places that do not depend on each other**:

1. The addresses `derive.py` prints.
2. The addresses your own wallet shows (Sparrow, Electrum, BlueWallet, any BIP84 tool).
3. The addresses on BoreLine's **Verify ZPUB** page in your dashboard.

If all three match, you have proven that every invoice pays out to an address only your wallet controls. BoreLine derives them the same standard way, and cannot substitute its own, because it never holds your private keys.

## 3. Check the tamper fingerprint

BoreLine stores only a SHA-256 fingerprint of your ZPUB and checks the stored key against it before deriving any address. The fingerprint on your Verify page must equal `SHA-256(your zpub)`, which `derive.py` also prints. If it ever changes without your action, that is a signal to stop and contact support.

## 4. Do a live test with nothing at stake

The strongest proof is watching it work with your own coins:

1. Register a **fresh ZPUB from a brand new wallet that holds zero funds** (the free Genesis tier is made for exactly this).
2. On the Verify page, check the derived address against that wallet and approve it.
3. Create an invoice for a tiny amount, five dollars for example.
4. Pay it yourself and watch where the money lands. It goes straight to your wallet, never through BoreLine.
5. Repeat as many times as you like.

Only once you have seen it work with your own eyes and your own coins do you register the wallet for your real business.

## Why this is trustworthy

- The derivation is **standard BIP84**, the same math every Bitcoin wallet uses. You are not trusting BoreLine's version, you are checking it against your own.
- The flow is **fixed in code**, it does not change between the test and production.
- Nothing here exposes a private key or seed. You verify using only public keys and addresses.

See also the [threat model](threat-model.md) for what an attacker can and cannot do, and the [security model](security-model.md) for what is stored and what is never seen.
