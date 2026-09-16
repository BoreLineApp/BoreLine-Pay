# Threat model

Security is about being honest, so here is plainly what an attacker can and cannot do against a BoreLine merchant, scenario by scenario. The short version: your funds are safe because BoreLine only ever holds a watch-only public key, and spending always requires your physical hardware device.

## What BoreLine can never do

By design, not by policy:

- **Move, freeze, or reverse your funds.** BoreLine holds a ZPUB (a public key). It cannot spend.
- **Change where your money goes without your device.** Rerouting requires a signature from your current hardware wallet, then a signature from the new one, then a 48 hour hold.
- **Sign in as you.** Login is a signature from your hardware wallet. There is no password to steal.
- **Recover or leak a usable API key.** Keys are stored only as SHA-256 hashes and shown once at creation.

## Assets and who holds them

| Asset | Held by | If exposed |
|-------|---------|------------|
| Seed phrase / private keys | You only, on your hardware wallet | Total loss. Never share, never type it anywhere. |
| ZPUB (public key) | You and BoreLine | Privacy only, not theft. See below. |
| API key | You (raw), BoreLine (hash only) | Someone could create invoices to *your own* wallet. Rotate it. |
| Webhook secret | You and BoreLine | Someone could forge payment notifications to your endpoint. Rotate it. |
| Session token | Your browser | A stolen session can view the dashboard, but cannot change the ZPUB or move funds without your device. |

## Attacker scenarios

**Your ZPUB leaks.** It is view-only. An attacker can see your addresses, balance, and history for that wallet. They cannot spend, sign in, or change anything. This is a privacy concern, not theft. Mitigation: use a dedicated business wallet and sweep funds to cold storage regularly.

**Your username leaks.** It is just a label. Signing in still requires a signature from your hardware device, so a known username gives an attacker nothing on its own.

**Your login session is hijacked.** The attacker can read dashboard data. They still cannot change your registered ZPUB (that needs a fresh signature from your current physical device) and cannot move funds. Sessions expire on a rolling window and can be revoked.

**An API key leaks.** The worst case is that someone creates invoices that pay into *your own* wallet, they cannot redirect money to themselves. Rotate the key from the dashboard and the old one dies instantly.

**BoreLine's server or database is compromised.** An attacker still cannot spend your funds (no private keys exist to steal) and cannot silently reroute them, because the server enforces a SHA-256 fingerprint check on the stored ZPUB before deriving any address. If the stored key were altered, derivation halts and the account locks. The blast radius is limited to public data and one-way hashes.

**A network attacker (man in the middle).** Traffic is TLS. Login, wallet-change, key-management and account-deletion authorizations are single-use, challenge-bound signatures, so a captured request cannot be replayed.

**Your hardware device is lost or stolen.** This is the one that matters. Whoever holds your device and PIN can act as you. Report it so wallet changes are suspended, move funds using your seed backup on a fresh device, and re-register.

## Your responsibilities

BoreLine removes custody risk, but self-custody means you own key safety:

- Keep your **seed phrase** backed up offline and never share or type it.
- Use a **dedicated business wallet**, separate from savings.
- Store your **API key** server-side only, never in front-end code.
- **Verify** your derived addresses before going live (see [verify-it-yourself.md](verify-it-yourself.md)).

## Honest limitations

- BoreLine is infrastructure, not custody and not insurance. It cannot recover, refund, or reverse a payment. Bitcoin transactions are final.
- A lost seed phrase means lost funds, exactly as in any self-custody setup.
- Confirmation times depend on the Bitcoin network, not on BoreLine.
