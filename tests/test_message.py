import base64
import unittest

from sign.message import (
    bitcoin_sign_message,
    ecdsa_sign_message,
    ecdsa_verify_message,
    verify_legacy_message,
    verify_p2wpkh_message,
)


PRIVATE_KEY_HEX = "00" * 31 + "01"
MESSAGE = "hello"
BIP322_PRIVATE_KEY_HEX = "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004"
BIP322_ADDRESS = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
BIP322_HELLO_WORLD_SIGNATURE = (
    "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcP"
    "ScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSF"
    "SajuFwrDL1Yhy"
)


class MessageSignatureTest(unittest.TestCase):
    def test_ecdsa_sign_and_verify_message(self):
        result = ecdsa_sign_message(PRIVATE_KEY_HEX, MESSAGE)

        self.assertEqual(result["signature_format"], "DER")
        self.assertRegex(result["signature"], r"^[0-9a-f]+$")
        self.assertTrue(
            ecdsa_verify_message(
                result["public_key_compressed"],
                MESSAGE,
                result["signature"],
            )
        )
        self.assertTrue(
            ecdsa_verify_message(
                result["public_key_uncompressed"],
                MESSAGE,
                result["signature"],
            )
        )

    def test_ecdsa_verify_rejects_wrong_message(self):
        result = ecdsa_sign_message(PRIVATE_KEY_HEX, MESSAGE)

        self.assertFalse(
            ecdsa_verify_message(
                result["public_key_compressed"],
                "not hello",
                result["signature"],
            )
        )

    def test_bitcoin_core_legacy_sign_and_verify(self):
        result = bitcoin_sign_message(PRIVATE_KEY_HEX, MESSAGE)["legacy"]
        compact_signature = base64.b64decode(result["signature_base64"])

        self.assertEqual(result["address"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        self.assertEqual(len(compact_signature), 65)
        self.assertIn(compact_signature[0], range(31, 35))
        self.assertTrue(
            verify_legacy_message(
                result["address"],
                MESSAGE,
                result["signature_base64"],
            )
        )
        self.assertFalse(
            verify_legacy_message(
                result["address"],
                "not hello",
                result["signature_base64"],
            )
        )

    def test_bip322_signing_matches_official_p2wpkh_vector(self):
        result = bitcoin_sign_message(
            BIP322_PRIVATE_KEY_HEX,
            "Hello World",
        )["p2wpkh"]

        self.assertEqual(result["address"], BIP322_ADDRESS)
        self.assertEqual(
            result["message_hash"],
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
        )
        self.assertEqual(result["signature_base64"], BIP322_HELLO_WORLD_SIGNATURE)
        self.assertTrue(
            verify_p2wpkh_message(
                BIP322_ADDRESS,
                "Hello World",
                BIP322_HELLO_WORLD_SIGNATURE,
            )
        )
        self.assertTrue(
            verify_p2wpkh_message(
                BIP322_ADDRESS,
                "Hello World",
                BIP322_HELLO_WORLD_SIGNATURE.removeprefix("smp"),
            )
        )

    def test_bip322_verification_rejects_wrong_message_and_address(self):
        self.assertFalse(
            verify_p2wpkh_message(
                BIP322_ADDRESS,
                "not Hello World",
                BIP322_HELLO_WORLD_SIGNATURE,
            )
        )
        self.assertFalse(
            verify_p2wpkh_message(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "Hello World",
                BIP322_HELLO_WORLD_SIGNATURE,
            )
        )


if __name__ == "__main__":
    unittest.main()
