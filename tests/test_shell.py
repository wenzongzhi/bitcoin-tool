import unittest

from bitcoin_tool import (
    BitcoinToolLexer,
    _shell_command_matches,
    _shell_option_matches,
    _split_shell_arguments,
)


class FakeDocument:
    def __init__(self, *lines):
        self.lines = list(lines)


class ShellTest(unittest.TestCase):
    def test_shell_argument_splitting_preserves_windows_paths(self):
        self.assertEqual(
            _split_shell_arguments('--datadir "E:\\wallet data" --change'),
            ["--datadir", "E:\\wallet data", "--change"],
        )

    def test_shell_completion_uses_argparse_commands_and_options(self):
        self.assertIn("ecdsa-sign", _shell_command_matches("ecdsa"))
        self.assertIn("ecdsa-verify", _shell_command_matches("ecdsa"))
        self.assertIn("bitcoin-sign-message", _shell_command_matches("bitcoin"))
        self.assertIn("bitcoin-verify-message", _shell_command_matches("bitcoin"))
        self.assertIn("getnewaddress", _shell_command_matches("get"))
        self.assertIn("gettransactionstatus", _shell_command_matches("get"))
        self.assertIn("convert", _shell_command_matches("con"))
        self.assertIn("createrawtransaction", _shell_command_matches("create"))
        self.assertIn("sendrawtransaction", _shell_command_matches("send"))
        self.assertIn("sendtoaddress", _shell_command_matches("send"))
        self.assertIn("sendall", _shell_command_matches("send"))
        self.assertNotIn("shell", _shell_command_matches("sh"))
        self.assertIn("--string", _shell_option_matches("hash", "--s"))
        self.assertIn("--private-key-hex", _shell_option_matches("ecdsa-sign", "--p"))
        self.assertIn("--public-key-hex", _shell_option_matches("ecdsa-verify", "--p"))
        self.assertIn("--sign", _shell_option_matches("ecdsa-verify", "--s"))
        self.assertIn(
            "--wallet-name",
            _shell_option_matches("bitcoin-sign-message", "--w"),
        )
        self.assertIn(
            "--p2wpkh-addr",
            _shell_option_matches("bitcoin-verify-message", "--p"),
        )
        self.assertIn("--wallet-name", _shell_option_matches("getnewaddress", "--w"))
        self.assertIn(
            "--address-type",
            _shell_option_matches("getnewaddress", "--a"),
        )
        self.assertEqual(_shell_option_matches("createwallet", "--m"), ["--mnemonic"])
        self.assertIn(
            "--fee-rate-sat-vb",
            _shell_option_matches("fundrawtransaction", "--f"),
        )
        self.assertIn("--dry-run", _shell_option_matches("sendtoaddress", "--d"))
        self.assertIn("--dry-run", _shell_option_matches("sendall", "--d"))
        self.assertEqual(_shell_option_matches("sendall", "--i"), [])
        self.assertIn("--entropy-hex-to-mnemonic", _shell_option_matches("convert", "--e"))
        self.assertIn("--mnemonic-to-entropy-hex", _shell_option_matches("convert", "--m"))

    def test_shell_lexer_styles_strings_and_options(self):
        lexer = BitcoinToolLexer()
        fragments = lexer.lex_document(FakeDocument('hash -s "Satoshi Nakamoto"'))(0)
        self.assertIn(("class:command", "hash"), fragments)
        self.assertIn(("class:option", "-s"), fragments)
        self.assertIn(("class:string", '"Satoshi Nakamoto"'), fragments)


if __name__ == "__main__":
    unittest.main()
