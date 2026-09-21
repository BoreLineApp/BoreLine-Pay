# BoreLine Pay

### Accept Bitcoin. Own every sat.

*BoreLine Pay is a service of **BoreLine App**.*

[![Website](https://img.shields.io/badge/website-boreline.app-f0b429)](https://boreline.app) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Custody](https://img.shields.io/badge/custody-non--custodial-2ea043) ![Transaction fees](https://img.shields.io/badge/transaction%20fees-0%25-f0b429) ![Bitcoin](https://img.shields.io/badge/Bitcoin-BIP84%20native%20SegWit-f7931a)

**Non-custodial Bitcoin payment infrastructure.** Accept Bitcoin payments that settle directly to a wallet only you control. BoreLine never holds, touches, or is able to move your funds at any point.

- Official site: **[BoreLine Pay — non-custodial Bitcoin payments](https://boreline.app)**
- [Whitepaper](https://boreline.app/whitepaper)
- [Integration guide](https://boreline.app/integrate)
- [Security guide](https://boreline.app/security)

> This repository is public and safe to read: it contains **no** server code, credentials, or anything that could compromise a merchant account. It holds two things. **Documentation and integration examples** explain how BoreLine works and help you integrate. And [**`verifiable-core/`**](verifiable-core/) is not a demo, it is the real verification toolkit, the exact address derivation BoreLine runs, that a merchant uses to check for themselves, at any time and around the clock, that every address BoreLine issues belongs to their own wallet. Verify us, do not trust us.

---

## What it is

BoreLine Pay lets a business accept Bitcoin without a custodian standing between the business and its money.

You register the extended public key (**ZPUB**, a BIP84 native SegWit *watch-only* key) from your own hardware wallet. From that key alone, BoreLine:

1. derives a unique Bitcoin address for each invoice,
2. watches the public blockchain for the payment, and
3. notifies your site the moment it confirms.

The Bitcoin goes **straight from your customer to your own wallet**. It never passes through BoreLine. That is a structural property of the design, not a policy we could change.

## How it works

```mermaid
flowchart LR
    M[Merchant] -->|1. registers ZPUB<br/>public key only| B[BoreLine Pay]
    B -->|2. derives a unique<br/>address per invoice| ADDR[Invoice address]
    C[Customer] -->|3. pays Bitcoin| ADDR
    ADDR ==>|on chain, directly| MW[Your own wallet]
    B -.->|4. observes the chain,<br/>signed webhook on confirm| M
    linkStyle 3 stroke:#16a34a,stroke-width:3px
```

The money path in green, from your customer straight to your wallet, never touches BoreLine. BoreLine only reads the public chain and derives addresses from a public key.

## Screenshots

### Merchant dashboard

Register your ZPUB, define products, and watch payments settle straight to your wallet. BoreLine takes zero fees and never touches the funds.

![BoreLine Pay merchant dashboard](assets/dashboard.png)

### Products and payment links

Reusable price tiers, each with its own hosted payment link that drops into a checkout or the API.

![Products page](assets/products.png)

### What your customer sees

A hosted Bitcoin payment page with the exact amount, a QR code, and a receiving address derived from your own wallet.

![Hosted Bitcoin payment page](assets/payment-page.png)

For physical products, the same page collects the buyer's shipping and contact details first, no extra code on your side.

![Shipping and contact form](assets/shipping.png)

### Verify, do not trust

The Verify page shows the derivation path, the ZPUB fingerprint, and the derived addresses, so you can confirm them against your own wallet before going live.

![Verify ZPUB page](assets/verify-page.png)

The derived-address list lines up character for character with your own wallet, and with the [`verifiable-core/`](verifiable-core/) script in this repo.

![Derived addresses on the Verify page](assets/verify-addresses.png)

## Why it is safe by design

- **Non-custodial.** BoreLine cannot hold, freeze, reverse, or move your funds. There is no balance held on your behalf.
- **Watch-only key.** A ZPUB can generate receiving addresses but can never spend. Your private keys and seed phrase never leave your hardware wallet, and BoreLine never sees them.
- **Tamper detection.** BoreLine stores a SHA-256 fingerprint of your ZPUB and re-checks it before deriving any address. If it ever fails to match, the account locks and no payment can be routed to an altered key.
- **No passwords.** You authenticate by signing a challenge with your hardware wallet. API keys are stored only as SHA-256 hashes.
- **No KYC.** You sign in with a wallet signature, not identity documents. BoreLine collects no name, ID, or personal data in order to receive payments.
- **Verify, do not trust.** A dashboard verification page shows the derivation path, the fingerprint, and the derived addresses so you can confirm them against your own wallet before going live.

## Verify it yourself (open source core)

You do not have to take the non-custodial claim on faith. The [`verifiable-core/`](verifiable-core/) folder contains the **exact address-derivation logic BoreLine uses**, as a standalone, dependency-free Python module you can read and run. It proves that every invoice address is a standard BIP84 address derived from your own public key, so payments can only land in a wallet you control.

```bash
cd verifiable-core
python derive.py <your-zpub> 5     # print your first addresses + fingerprint
python test_vectors.py             # verify the code against the BIP84 spec
```

Line up the output against your own wallet (Sparrow, Electrum, ...) and BoreLine's Verify page. If all three match, non-custody is proven, not promised. The module contains no secrets, no keys, and makes no network calls. See [`verifiable-core/README.md`](verifiable-core/README.md).

This is not just a one-off check, and it is not just "derive your own addresses." Over a **read-only token** it fetches the addresses BoreLine actually issued for your invoices and **compares each against the one you derive locally from your own key**, two independent sources side by side. That is how you watch our server in real time without us revealing any secret. It can run **continuously**: `verify.html` re-checks on a timer while the tab is open, and `verify_invoices.py --watch` runs it unattended as a scheduled job (with an optional Telegram alert to your phone), so you are notified the moment an address does not derive from your key.

Running the verifier is **optional**: you never need it to accept payments, and skipping it changes nothing about how you get paid. It exists so the most security-conscious merchants can check us instead of trusting us, and we publish it because we are paranoid about security ourselves.

## Two ways to integrate

| Path | For whom | Needs code? |
|------|----------|-------------|
| **No-code payment links** | Most sellers. One link per product. Safe to share publicly, it carries no secret. | No |
| **REST API + signed webhooks** | Custom checkouts and automatic order fulfilment. | Yes, a backend |

The REST API and signed webhooks are available on the paid plans. The free **Genesis** tier is no-code: it uses hosted payment links.

### Quick look at the API

Create an invoice from **your backend** (never the browser):

```http
POST https://api.borelinepay.uk/api/invoice
X-API-Key: your_secret_api_key
Content-Type: application/json

{ "tier": "starter", "email": "customer@example.com", "months": 1 }
```

Response:

```json
{
  "invoice_url": "https://api.borelinepay.uk/pay/INV-...",
  "amount_sats": 51275,
  "fiat_amount": 29.00,
  "currency": "EUR",
  "expires_at": "2026-06-17T12:00:00Z"
}
```

Redirect the customer to `invoice_url`. BoreLine sends a signed webhook to your site when the payment confirms. Runnable examples are in [`examples/`](examples/), and the full reference is in [`docs/api-reference.md`](docs/api-reference.md).

## Pricing

A flat monthly subscription, paid in Bitcoin, with **no percentage taken from any transaction**.

| Plan | Price |
|------|-------|
| Genesis | Free for life (1 product) |
| Starter | EUR 20 / month |
| Pro | EUR 40 / month |
| Business | EUR 90 / month |

**Genesis** is free for life for a single product: unlimited sales, no card, no expiry, one free account per wallet. It is no-code (hosted payment links); the REST API and signed webhooks unlock on the paid plans. Verify the whole flow with a fresh empty wallet before committing a cent.

## How BoreLine compares

There are three broad ways to accept Bitcoin. BoreLine sits deliberately in the gap between a hosted convenience product and running your own server.

| | **BoreLine Pay** | Custodial processors (e.g. BitPay, OpenNode) | Self-hosted (e.g. BTCPay Server) |
|---|---|---|---|
| Custody of funds | **Non-custodial**, funds never touch BoreLine | Custodial, they hold then settle to you | Non-custodial |
| Where the money lands | **Your own wallet, directly on chain** | Their account first, then paid out to you | Your own wallet |
| Fees | **Flat monthly, no percentage per sale** | A percentage of each transaction | Free software, you pay hosting and upkeep |
| Setup | Register a ZPUB, nothing to host | Sign up | Deploy and maintain your own server |
| Who holds the keys | **You only**, on your hardware wallet | The provider, until payout | You only |
| Best for | Non-custodial payments without running infrastructure | Convenience and built-in fiat conversion | Technical users who want to self-host everything |

The trade-off is simple: custodial processors are convenient but hold your money and take a cut; self-hosting keeps custody but you run the server. BoreLine keeps the funds in your own wallet like self-hosting, while staying hosted and zero-maintenance like a processor, for a flat fee. These are general characteristics, always check each provider's current terms.

## Documentation in this repo

- [`docs/how-it-works.md`](docs/how-it-works.md) , the model and the payment lifecycle in plain terms
- [`docs/security-model.md`](docs/security-model.md) , what is stored, what is never seen, and the trust model
- [`docs/threat-model.md`](docs/threat-model.md) , what an attacker can and cannot do, scenario by scenario
- [`docs/verify-it-yourself.md`](docs/verify-it-yourself.md) , prove non-custody independently, do not trust, verify
- [`docs/api-reference.md`](docs/api-reference.md) , the invoice endpoint and webhook, field by field
- [`docs/faq.md`](docs/faq.md) , common questions
- [`verifiable-core/`](verifiable-core/) , the real address-derivation logic, runnable, so you can verify non-custody yourself

## Contact

Questions, security disclosure, or integration help: **borelineapp@proton.me**

Responsible disclosure is welcome. BoreLine Pay will never ask for your seed phrase or private keys, and neither will anyone legitimate.

## Contributing and security

Contributions to the docs and examples are welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a vulnerability, see [`SECURITY.md`](SECURITY.md) and email **borelineapp@proton.me** privately. Please do not open a public issue for a security problem.

## License

The example code and documentation in this repository are released under the [MIT License](LICENSE). "BoreLine Pay" and the BoreLine brand are property of BoreLine Pay.
