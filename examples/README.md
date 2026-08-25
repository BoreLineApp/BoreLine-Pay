# Examples

Runnable, minimal examples of the two things you do with the BoreLine API:

1. **Create an invoice** from your backend and get a payment link.
2. **Verify a webhook** signature before acting on a payment notification.

Both come in Node.js and Python. They read your API key and webhook secret from **environment variables**, never hardcode secrets.

```bash
export BORELINE_API_KEY="your_secret_api_key"      # from your dashboard
export BORELINE_WEBHOOK_SECRET="your_webhook_secret"
```

> The webhook example verifies with your **Webhook Secret** (dashboard Settings page, separate from your API key). BoreLine sends the signature in `X-BoreLine-Sig` and the send time in `X-BoreLine-Time`.

- Node.js: [`nodejs/`](nodejs/) (needs Node 18+ for built-in `fetch`)
- Python: [`python/`](python/) (needs `requests` for the invoice example)
