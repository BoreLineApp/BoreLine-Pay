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

## Please avoid

- Denial-of-service testing against the live service.
- Automated scanning that degrades service for other merchants.
- Accessing, modifying, or exfiltrating data that is not your own.
- Social engineering of BoreLine staff, merchants, or their customers.

## A note on impersonation

BoreLine Pay will **never** ask for your seed phrase or private keys, and will never contact you first asking you to move funds or take urgent action with your account. Anyone who does is an impostor, even if they use our name. Legitimate security researchers will never need your seed phrase either.
