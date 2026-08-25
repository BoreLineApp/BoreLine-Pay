# API reference

The BoreLine API is small on purpose: create an invoice, then receive a signed webhook when it is paid. This mirrors the public [integration guide](https://boreline.app/integrate).

Base URL: `https://api.borelinepay.uk`

> **Always call the API from your backend.** Your API key is a secret and must never be shipped to the browser, a mobile app, or any code a visitor can inspect. A leaked key lets a stranger create invoices on your account.

---

## Create an invoice

```
POST /api/invoice
```

**Headers**

| Header | Value |
|--------|-------|
| `X-API-Key` | your secret API key |
| `Content-Type` | `application/json` |

**Body**

| Field | Required | Description |
|-------|----------|-------------|
| `tier` | yes | The product key you set in your dashboard, for example `starter` or `pro`. |
| `email` | no | A label to tie the payment to a customer or order on your side. BoreLine never emails anyone. |
| `months` | no | Defaults to `1`. Useful if you sell access in multiples. |
| `note` | no | A free-text note you attach to the invoice. |
| `metadata` | no | A JSON object to carry your own order id or any reference. |

**Example request**

```json
{
  "tier": "starter",
  "email": "customer@example.com",
  "months": 1,
  "metadata": { "order_id": "A-1042" }
}
```

**Example response**

```json
{
  "invoice_url": "https://api.borelinepay.uk/pay/INV-...",
  "amount_sats": 51275,
  "fiat_amount": 29.00,
  "currency": "EUR",
  "expires_at": "2026-06-17T12:00:00Z"
}
```

| Field | Description |
|-------|-------------|
| `invoice_url` | The hosted payment page. Redirect the customer here. It shows the amount, a QR code, and the address, and collects shipping details if the product has **Ship** enabled. |
| `amount_sats` | The amount due, in satoshis. |
| `fiat_amount` / `currency` | The fiat value the amount was priced at. |
| `expires_at` | When the invoice expires (ISO 8601, UTC). |

A `btc_address` is also returned for merchants who build a fully custom payment screen instead of using the hosted page. Most integrations should just redirect to `invoice_url`.

---

## Webhook: payment confirmed

Set a webhook URL in your dashboard settings. When a payment confirms on chain, BoreLine sends a request to that URL containing the product, the invoice id, and any reference you attached (such as `email` or your `metadata`). Your site reacts however you need: mark the order paid, send a download, or grant access.

- If a payment is later reversed by a rare blockchain reorganisation, you receive a **second alert** so you can undo access.
- If your site is briefly down when an alert is sent, BoreLine **retries automatically**.

### Verifying the webhook signature

Every webhook is cryptographically signed so you can confirm it truly came from BoreLine. **Verify the signature before acting on the payload.**

Compute `HMAC-SHA256(raw_body)` keyed with your **Webhook Secret** (shown on the dashboard Settings page, separate from your API key), and compare it in constant time against the header BoreLine sends. Headers on every webhook:

| Header | Meaning |
|--------|---------|
| `X-BoreLine-Sig` | the HMAC-SHA256 signature, hex |
| `X-BoreLine-Time` | unix seconds when sent, reject if older than a few minutes to stop replay |
| `X-BoreLine-Event` | `payment.confirmed`, `payment.late`, or `payment.reversed` |

See [`../examples/`](../examples/) for a worked example in Node.js and Python.

Never trust a webhook whose signature does not verify, and always compare using a constant-time comparison to avoid timing attacks.
