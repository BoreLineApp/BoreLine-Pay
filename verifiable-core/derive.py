#!/usr/bin/env python3
"""BoreLine Pay , verifiable address derivation (reference implementation).

This is the exact logic BoreLine uses to turn your ZPUB into receiving
addresses, extracted as a standalone, dependency-free module so anyone can run
it and audit it. It proves the core non-custodial claim: every invoice address
is a standard BIP84 address derived from *your* public key, so payments can only
land in a wallet you control. BoreLine cannot reroute them.

It contains NO secrets and makes NO network calls. Give it a public ZPUB and it
prints:

  * the SHA-256 fingerprint of the ZPUB (the same value shown on BoreLine's
    Verify page), and
  * the first receiving addresses (derivation path m/0/index).

Compare these against your own wallet (Sparrow, Electrum, BlueWallet, or any
BIP84 tool) and against BoreLine's dashboard. If they match, you have proven,
without trusting BoreLine, that funds derive to addresses only your wallet
controls. A ZPUB is watch-only: it can generate addresses but can never spend.

Pure Python 3 standard library. No `pip install` needed.

Usage:
    python derive.py <zpub> [count]
    python derive.py <zpub> --check <bc1q-address>
"""

import hashlib
import hmac
import re
import struct
import sys

# ── secp256k1 curve parameters ──────────────────────────────────────────
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ── extended-key version bytes (mainnet) ────────────────────────────────
# BoreLine derives BIP84 native SegWit only, so it accepts a zpub and nothing
# else. The other versions are listed purely so we can name what a merchant
# pasted and point them at the right key, instead of silently printing bech32
# addresses that will never match a BIP44/BIP49 wallet.
_VER_BIP84 = 0x04B24746  # zpub , BIP84 P2WPKH   (bc1q...)
_VER_BIP49 = 0x049D7CB2  # ypub , BIP49 P2SH-segwit (3...)
_VER_BIP44 = 0x0488B21E  # xpub , BIP44 legacy   (1...)

_VER_NAMES = {
    _VER_BIP84: "zpub (BIP84, native SegWit)",
    _VER_BIP49: "ypub (BIP49, wrapped SegWit)",
    _VER_BIP44: "xpub (BIP44, legacy)",
}


# ── hashing helpers ─────────────────────────────────────────────────────
def _sha256d(d):
    return hashlib.sha256(hashlib.sha256(d).digest()).digest()


def _h160(d):
    return hashlib.new("ripemd160", hashlib.sha256(d).digest()).digest()


def _hmac512(k, d):
    return hmac.new(k, d, hashlib.sha512).digest()


# ── base58check decode ──────────────────────────────────────────────────
def _b58dec(s):
    s = s.encode() if isinstance(s, str) else s
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for c in s:
        if c == _B58[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + full


# ── secp256k1 point math (enough to derive child public keys) ────────────
def _padd(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if P[1] != Q[1]:
            return None
        m = (3 * P[0] * P[0] * pow(2 * P[1], _P - 2, _P)) % _P
    else:
        m = ((Q[1] - P[1]) * pow(Q[0] - P[0], _P - 2, _P)) % _P
    x = (m * m - P[0] - Q[0]) % _P
    return (x, (m * (P[0] - x) - P[1]) % _P)


def _pmul(k, P):
    R = None
    while k:
        if k & 1:
            R = _padd(R, P)
        P = _padd(P, P)
        k >>= 1
    return R


def _compress(pt):
    x, y = pt
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")


def _child_pub(pk, cc, idx):
    """Non-hardened BIP32 child public key derivation from a parent pubkey."""
    if type(idx) is not int or not 0 <= idx < 0x80000000:
        raise ValueError("Public derivation requires a non-hardened integer index")
    if len(pk) != 33 or pk[0] not in (2, 3):
        raise ValueError("Invalid parent key , expected a compressed public key")
    if len(cc) != 32:
        raise ValueError("Invalid parent key , chain code must be 32 bytes")
    I = _hmac512(cc, pk + struct.pack(">I", idx))
    IL = int.from_bytes(I[:32], "big")
    if IL >= _N:
        raise ValueError("Invalid child key , index produced unusable key")
    G = (_Gx, _Gy)
    x = int.from_bytes(pk[1:], "big")
    if x >= _P:
        raise ValueError("Invalid parent key , x coordinate is outside the field")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    # Modular sqrt only returns a valid root if one exists; confirm the point
    # is actually on secp256k1 before trusting it (rejects a malformed pubkey).
    if (y * y) % _P != y_sq:
        raise ValueError("Invalid parent key , point is not on the curve")
    if (y % 2) != (pk[0] - 2):
        y = _P - y
    child = _padd(_pmul(IL, G), (x, y))
    if child is None:
        raise ValueError("Invalid child key , point at infinity")
    return _compress(child), I[32:]


# ── bech32 encode (BIP173) ──────────────────────────────────────────────
_B32C = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _b32poly(v):
    G = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    c = 1
    for x in v:
        b = c >> 25
        c = (c & 0x1FFFFFF) << 5 ^ x
        for i in range(5):
            c ^= G[i] if (b >> i) & 1 else 0
    return c


def _cvbits(data, fb, tb, pad=True):
    acc = 0
    bits = 0
    ret = []
    mx = (1 << tb) - 1
    for v in data:
        acc = ((acc << fb) | v) & ((1 << (fb + tb - 1)) - 1)
        bits += fb
        while bits >= tb:
            bits -= tb
            ret.append((acc >> bits) & mx)
    if pad and bits:
        ret.append((acc << (tb - bits)) & mx)
    return ret


def _b32enc(hrp, wv, wp):
    data = [wv] + _cvbits(wp, 8, 5)
    hrpe = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = _b32poly(hrpe + data + [0] * 6) ^ 1
    cs = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_B32C[d] for d in data + cs)


# ── public API ──────────────────────────────────────────────────────────
def extract_zpub(raw):
    """Pull a usable extended public key out of common paste formats:
    plain 'zpub...', surrounding quotes/whitespace, or an output descriptor
    like 'wpkh([abcd/84h/0h/0h]zpub.../0/*)'. Returns the cleaned key or ''.
    """
    if not raw:
        return ""
    s = "".join(str(raw).strip().strip('"').strip("'").split())
    m = re.search(r"((?:zpub|xpub|ypub|upub|vpub|tpub)[1-9A-HJ-NP-Za-km-z]{50,140})", s)
    return m.group(1) if m else s


def fingerprint(zpub):
    """SHA-256 fingerprint of the ZPUB string.

    This is exactly the value BoreLine stores and shows on the Verify page. It
    is a one-way hash of the *public* key, used to detect tampering. It reveals
    nothing that could move funds.
    """
    return hashlib.sha256(zpub.encode()).hexdigest()


def key_version(zpub):
    """Return the 4-byte version prefix of an extended key as an int, or -1."""
    try:
        raw = _b58dec(zpub)
        if len(raw) < 4:
            return -1
        return int.from_bytes(raw[:4], "big")
    except (ValueError, IndexError):
        return -1


def derive_address(zpub, index):
    """Derive the native SegWit (bc1q) address at path m/0/{index} from a ZPUB.

    The ZPUB is the account-level key (m/84'/0'/0'). We derive the external
    chain (/0) then the address index (/index), per BIP84. Verified against the
    official BIP84 test vectors (see README).

    BIP84 (zpub) only. An xpub (BIP44) or ypub (BIP49) encodes a different
    script type, so deriving bech32 from it would print addresses that never
    match the wallet. Those are rejected here rather than silently mis-derived.
    """
    raw = _b58dec(zpub)
    if len(raw) != 82:
        raise ValueError("ZPUB must contain a 78-byte payload and 4-byte checksum")
    payload, chk = raw[:-4], raw[-4:]
    if _sha256d(payload)[:4] != chk:
        raise ValueError("ZPUB checksum invalid , key may be corrupted or truncated")
    ver = int.from_bytes(payload[:4], "big")
    if ver != _VER_BIP84:
        got = _VER_NAMES.get(ver, "an unrecognized key type")
        raise ValueError(
            "This is %s. BoreLine derives BIP84 native SegWit only, so it needs "
            "a zpub. Export the zpub (account m/84'/0'/0') from your wallet and "
            "use that." % got
        )
    cc = payload[13:45]
    pk = payload[45:78]
    pk, cc = _child_pub(pk, cc, 0)       # external chain m/0
    pk, _ = _child_pub(pk, cc, index)    # address index m/0/index
    addr = _b32enc("bc", 0, _h160(pk))
    if not addr.startswith("bc1q"):
        raise ValueError("Derived address has unexpected format")
    return addr


def address_belongs_to_zpub(zpub, address, window=100):
    """Return the index at which `address` derives from `zpub`, else -1.

    Scans the first `window` receiving addresses. Proves an address is truly
    controlled by the wallet behind the ZPUB.
    """
    for i in range(window):
        if derive_address(zpub, i) == address:
            return i
    return -1


def _main(argv):
    if not argv:
        print(__doc__)
        return 1

    zpub = extract_zpub(argv[0])
    ver = key_version(zpub)
    if ver != _VER_BIP84:
        if ver in _VER_NAMES:
            print("error: that looks like %s." % _VER_NAMES[ver], file=sys.stderr)
            print("       BoreLine is BIP84 only , export your zpub (account "
                  "m/84'/0'/0') and use that.", file=sys.stderr)
        else:
            print("error: expected a zpub (BIP84 native SegWit extended public "
                  "key).", file=sys.stderr)
        return 2

    print("BIP84 only , expects a zpub (native SegWit, bc1q addresses).")
    print()
    print("ZPUB fingerprint (SHA-256):")
    print("  " + fingerprint(zpub))
    print()

    if len(argv) >= 3 and argv[1] == "--check":
        target = argv[2].strip()
        idx = address_belongs_to_zpub(zpub, target)
        if idx >= 0:
            print("MATCH: %s derives from this ZPUB at m/0/%d" % (target, idx))
            return 0
        print("NO MATCH: %s was not found in the first 100 addresses" % target)
        return 1

    count = int(argv[1]) if len(argv) >= 2 else 5
    print("First %d receiving addresses (path m/0/index):" % count)
    for i in range(count):
        print("  m/0/%-4d  %s" % (i, derive_address(zpub, i)))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
