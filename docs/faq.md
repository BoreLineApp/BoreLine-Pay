# FAQ

### Do you ever hold my Bitcoin?

No. BoreLine derives receiving addresses from your ZPUB, a view-only public key. Payments go straight from the customer to your own hardware wallet. BoreLine has no ability to move your funds under any circumstances.

### What is a ZPUB, and is it safe to give you?

A ZPUB (or XPUB) is a view-only extended public key from your hardware wallet. It lets BoreLine generate unique receiving addresses without any ability to spend. Registering it is not handing over custody. Your private keys and seed phrase never leave your device and are never seen by BoreLine.

### Where do I find my ZPUB?

- **Trezor Suite:** open the account, then Show public key.
- **Ledger Live:** open the account, then Edit, then Advanced.
- **Sparrow:** the Master Public Keys section.
- **Other wallets:** look for Export, Master public key, or xpub in the wallet settings.

Native SegWit accounts give a key starting with `zpub`. Keys starting with `xpub` or `ypub` also work.

### How is BoreLine priced?

A flat monthly subscription paid in Bitcoin: Starter EUR 29, Pro EUR 49, Business EUR 99 per month. No percentage is taken from any transaction. A 7-day free trial with the full Starter feature set requires no payment.

### Do I need to be a developer?

No. Most sellers use no-code payment links, one per product, with nothing to install. The API is only for custom checkouts and automatic fulfilment.

### What happens if my ZPUB leaks?

A leaked ZPUB is a privacy concern, not a theft risk. Someone with it can see your addresses and balance for that wallet but cannot spend, sign in, or change anything. This is why a dedicated business wallet and regular sweeping to cold storage are recommended.

### How do I know payments will really arrive at my wallet?

Verify it yourself. Your dashboard's Verify page shows the derivation path, the ZPUB fingerprint, and the derived addresses. Compare them against your own wallet software. Even better, use the free trial with a fresh empty wallet: create a small invoice, pay it, and watch the money land in your wallet before you commit.

### Can I accept payments for physical goods?

Yes. Enable **Ship** on a product and the hosted payment page collects the buyer's name, address, and contact before payment. Those details appear in your dashboard and webhook and are deleted after 90 days.

### Who do I contact?

Email **borelineapp@proton.me** for support or responsible security disclosure.
