# Security Policy

BoreLine Pay is non-custodial Bitcoin payment infrastructure. Security is the product, and responsible disclosure is genuinely welcome.

## Reporting a vulnerability

If you find a bug, a vulnerability, or anything that looks off, please email:

**borelineapp@proton.me**

For a suspected security issue, report it **privately first** and give us a chance to fix it before it goes public. Please do not open a public GitHub issue for a security problem.

Helpful things to include:

- A clear description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected surface (website, API, hosted payment page, dashboard).

We aim to acknowledge reports within one business day.

## Scope

This repository contains public documentation and example code only. It holds no server code, credentials, or infrastructure. Vulnerability reports about the live service (boreline.app and the API host) are the ones that matter most and are always in scope.

## How BoreLine protects your stored ZPUB

A ZPUB is a watch-only public key. It can generate your receiving addresses but it can never spend, move funds, or reveal a private key. What it does expose to whoever holds it is visibility: your addresses, your balance, and your payment history. That makes it the most sensitive thing BoreLine stores on your behalf, and it is treated that way.

- **Watch-only by design.** Even a full database compromise cannot move a single sat. Non-custody is structural, not a promise you have to take on faith. You can prove it yourself with `verifiable-core/`.
- **Self-hosted, not a shared cloud database.** Merchant data lives on hardware BoreLine controls, behind a Cloudflare edge (TLS, WAF) with the admin surface blocked at the edge and reachable only over a private network.
- **Hardware-key admin access.** Administrative access is gated by a physical hardware-key (Trezor) signature rather than a password, so there is no admin credential to phish, reuse, or leak.
- **Redacted from logs.** ZPUBs and API keys are stripped from application logs, so the key is not scattered across log files.
- **Change-controlled.** Every ZPUB change is authenticated, recorded with before and after fingerprints, alerted, and held under a time embargo before it takes effect, so a silent swap is not possible.
- **Encrypted backups.** Off-box backups can be encrypted with a public key, so a stray backup file is not a plaintext dump.

The honest tradeoff of any hosted watch-only service is that the operator can see your public on-chain activity. What that visibility can never become is control of your funds. The worst case here is privacy, never loss.

## What is provable versus what you trust

BoreLine has two halves, and it is worth being explicit about which is which.

**Provable, no trust required.** Address derivation and the non-custodial guarantee are pure math you can reproduce. Everything under `verifiable-core/` is the exact derivation logic BoreLine uses; run it against your own ZPUB and confirm that every invoice address is a standard BIP84 address only your wallet controls. BoreLine cannot reroute a payment, because it never holds a key that could.

**Trust the service.** Everything else, watching the chain for incoming payments, firing webhooks, the dashboard, authentication, and subscription state, runs on BoreLine's hosted backend. This is "trust the service," the same posture as any payment processor: there can be downtime, bugs, or visibility into your public on-chain activity. What that trust can never cost you is custody. Funds land directly in your wallet, and no failure on the service side can redirect them.

Put plainly: BoreLine can affect whether you get a timely notification or a clean dashboard. It cannot affect whether you get paid.

## Please avoid

- Denial-of-service testing against the live service.
- Automated scanning that degrades service for other merchants.
- Accessing, modifying, or exfiltrating data that is not your own.
- Social engineering of BoreLine staff, merchants, or their customers.

## A note on impersonation

BoreLine Pay will **never** ask for your seed phrase or private keys, and will never contact you first asking you to move funds or take urgent action with your account. Anyone who does is an impostor, even if they use our name. Legitimate security researchers will never need your seed phrase either.
