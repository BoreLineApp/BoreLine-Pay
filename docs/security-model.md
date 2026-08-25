# Security model

BoreLine is built so that every claim can be verified by the merchant, independently, before any real money is involved. This page summarises what is stored, what is never seen, and why an exposed piece of data is or is not a risk. The full treatment is in the [whitepaper](https://boreline.app/whitepaper) and the [security guide](https://boreline.app/security).

## What is stored, and is harmless

- **Your registered ZPUB**, a public key.
- **A SHA-256 fingerprint of the ZPUB**, used for tamper detection.
- **Invoice records and derived addresses.**
- **API keys, stored only as SHA-256 hashes.**

Everything above is either public information or a one-way hash. None of it can move a single satoshi.

## What is never stored and never seen

- **Your recovery phrase.**
- **Your private keys.**
- **Any spending authority.**
- **Customer card or bank details**, of which there are none, because payment is Bitcoin on chain.

## Why an exposed ZPUB is not a theft risk

A ZPUB is watch-only. Someone who has it can see your receiving addresses, your transaction history, and the balance of that wallet. They **cannot** spend, cannot sign in, and cannot change anything. An exposed ZPUB is a privacy consideration, not a theft risk. This is why BoreLine recommends a dedicated business wallet and sweeping received funds to cold storage regularly, the less it holds, the less anyone learns.

## Tamper detection on the key

Before deriving any payment address, the server recomputes the SHA-256 of the stored ZPUB and compares it to the stored fingerprint. If the two ever diverge, the sign of the ZPUB having been altered outside the signed change flow, the server refuses to derive, locks the account, and raises an alert. No payment can be routed to a substituted key. You can verify the same fingerprint yourself at any time on the Verify page.

## Authentication without passwords

There are no passwords to leak. You authenticate by signing a challenge message with your hardware wallet, cryptographically proving control of the registered account. API keys are shown in full only once, at creation, and are stored only as hashes, so a database of hashes cannot leak usable keys. If a key is lost, the answer is replacement, not recovery: generate a fresh key and the old one stops working immediately.

## Protected key changes

Changing the registered ZPUB requires **two signatures**, one from the current hardware device authorising the change and one from the incoming device proving control of the new key, followed by a security hold during which the previous ZPUB keeps receiving. An attacker who compromised a login session alone cannot silently redirect funds, because your physical signing device is still required.

## Webhook authenticity

Every webhook BoreLine sends is cryptographically signed so your server can confirm it genuinely came from BoreLine and not an impostor. **Always verify the signature before acting on a webhook.** See [`api-reference.md`](api-reference.md) and the webhook example in [`../examples/`](../examples/).

## Verify, do not trust

Each account includes a verification view showing the derivation path, the ZPUB fingerprint, and the derived addresses. Compare them against your own software (Trezor Suite, Ledger Live, Sparrow, or any BIP84-compatible tool). If the addresses match, you have proven, without trusting BoreLine, that payments arrive at your account and nowhere else. The recommended way to gain confidence is the free trial: register a fresh empty wallet, create a small invoice, pay it yourself, and watch the money land in your own wallet.
