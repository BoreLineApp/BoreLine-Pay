#!/usr/bin/env python3
"""Self-test for derive.py against the official BIP84 test vector.

Run:
    python test_vectors.py

Exit code 0 means every derivation matched. This lets anyone confirm the
reference implementation is correct without trusting it, using the published
BIP84 vector as an independent anchor (the index 1 address below is the exact
value from the BIP84 specification).

BIP84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
"""

import sys

import derive

# Official BIP84 account 0 extended public key. Mnemonic:
# "abandon abandon abandon abandon abandon abandon abandon abandon abandon
#  abandon abandon about"
ZPUB = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtf"
        "SdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")

# Derived receiving addresses, path m/0/index. Index 1 is the published BIP84
# specification vector; all three are checksum-valid native SegWit addresses.
EXPECTED = {
    0: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    1: "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    2: "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z",
}
EXPECTED_FINGERPRINT = "e06675e6ba2f9dddf8e87123bb2d426b1b2b663382d500e47e4f1126996fd074"


def main():
    passed = True

    for i, want in EXPECTED.items():
        got = derive.derive_address(ZPUB, i)
        good = got == want
        passed = passed and good
        print("[%s] m/0/%d  %s" % ("ok" if good else "FAIL", i, got))

    fp = derive.fingerprint(ZPUB)
    good_fp = fp == EXPECTED_FINGERPRINT
    passed = passed and good_fp
    print("[%s] fingerprint  %s" % ("ok" if good_fp else "FAIL", fp))

    idx = derive.address_belongs_to_zpub(ZPUB, EXPECTED[2])
    good_own = idx == 2
    passed = passed and good_own
    print("[%s] address_belongs_to_zpub -> index %d" % ("ok" if good_own else "FAIL", idx))

    print("\n" + ("ALL PASSED" if passed else "SOME FAILED"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
