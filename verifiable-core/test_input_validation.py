"""Reject invalid extended public keys and hardened public derivation.

Uses only the public BIP84 vector already included in test_vectors.py.
Run with: python -m unittest -v test_input_validation
"""

import unittest

import derive
from test_vectors import ZPUB, EXPECTED


def encode_payload(payload):
    """Base58Check encode a mutated public test vector, never a live key."""
    raw = payload + derive._sha256d(payload)[:4]
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = chr(derive._B58[digit]) + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + encoded


class InputValidationTests(unittest.TestCase):
    def setUp(self):
        self.payload = derive._b58dec(ZPUB)[:-4]

    def test_published_receiving_addresses_unchanged(self):
        for index in (0, 1):
            with self.subTest(index=index):
                self.assertEqual(derive.derive_address(ZPUB, index), EXPECTED[index])

    def test_highest_nonhardened_index_still_supported(self):
        self.assertTrue(derive.derive_address(ZPUB, 2**31 - 1).startswith("bc1q"))

    def test_hardened_public_derivation_is_rejected(self):
        for index in (2**31, 2**32 - 1):
            with self.subTest(index=index), self.assertRaises(ValueError):
                derive.derive_address(ZPUB, index)

    def test_invalid_index_values_are_rejected(self):
        for index in (-1, 2**32, 1.5, True):
            with self.subTest(index=index), self.assertRaises(ValueError):
                derive.derive_address(ZPUB, index)

    def test_wrong_serialized_length_is_rejected(self):
        for payload in (self.payload + b"\x00", self.payload + b"\x00\x00"):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                derive.derive_address(encode_payload(payload), 0)

    def test_noncompressed_public_key_prefix_is_rejected(self):
        for prefix in (0, 1, 4, 255):
            malformed = self.payload[:45] + bytes([prefix]) + self.payload[46:]
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                derive.derive_address(encode_payload(malformed), 0)

    def test_x_coordinate_outside_field_is_rejected(self):
        # Select an out-of-range x whose reduction has a square root so that
        # this specifically tests field bounds, not the existing curve test.
        for offset in range(32):
            x = derive._P + offset
            rhs = (pow(x, 3, derive._P) + 7) % derive._P
            y = pow(rhs, (derive._P + 1) // 4, derive._P)
            if pow(y, 2, derive._P) == rhs:
                malformed = self.payload[:45] + b"\x02" + x.to_bytes(32, "big")
                with self.assertRaises(ValueError):
                    derive.derive_address(encode_payload(malformed), 0)
                return
        self.fail("Could not construct the deterministic invalid-field vector")


if __name__ == "__main__":
    unittest.main()
