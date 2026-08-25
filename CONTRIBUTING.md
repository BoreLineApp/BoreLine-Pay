# Contributing

Thanks for your interest in BoreLine Pay.

## What this repository is

This is the **public documentation and example code** for BoreLine Pay. The BoreLine service itself (the server, the dashboard, the payment engine) is not open source and does not live here. What you can contribute to are the docs and the integration examples that help people understand and integrate with BoreLine.

## Good contributions

- **Fixes to the docs**: corrections, clearer wording, broken links.
- **New integration examples**: a clean, minimal example in another language or framework (Go, PHP, Ruby, a WordPress or Shopify snippet, and so on).
- **Improvements to existing examples**: clarity, error handling, comments.

## Ground rules

- **Never commit secrets.** No API keys, webhook secrets, ZPUBs, seed phrases, or `.env` files. All examples must read credentials from environment variables. The `.gitignore` blocks the common cases, but check your diff.
- Keep examples **backend-only** where an API key is involved. Never show a key in browser or client-side code.
- Match the existing style: small, readable, well commented, no heavy dependencies.
- Keep facts accurate. If in doubt about the API surface, check the live [integration guide](https://boreline.app/integrate) and [whitepaper](https://boreline.app/whitepaper).

## How to submit

1. Fork the repository and create a branch.
2. Make your change, and test any example code you touch.
3. Open a pull request with a short description of what and why.

## Security issues

Do **not** open a public issue for a security problem. See [`SECURITY.md`](SECURITY.md) and email **borelineapp@proton.me** privately.

## Questions

Anything else, email **borelineapp@proton.me**.
