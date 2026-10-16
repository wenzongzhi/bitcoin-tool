from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from bitcoin_tool import BitcoinToolShell, build_parser, run_cli, _shell_command_matches, _shell_option_matches
from single_key_wallet.tests.helpers import WalletFixture


class CliTest(WalletFixture):
    def test_commands_completion_and_fallback_shell(self):
        self.assertIn("singlekey-send", _shell_command_matches("singlekey-"))
        self.assertIn("--from-address-type", _shell_option_matches("singlekey-send", "--f"))
        shell = BitcoinToolShell("testnet4")
        with patch("bitcoin_tool.run_cli") as run:
            shell.onecmd("singlekey-getaddress --wallet-name test")
        run.assert_called_once_with(["--network", "testnet4", "singlekey-getaddress", "--wallet-name", "test"])

    def test_send_modes_required_and_mutually_exclusive(self):
        base = ["--network", "testnet4", "singlekey-send", "--wallet-name", "test", "--from-address-type", "p2wpkh",
                "--to", self.addresses["p2wpkh"]["address"], "--fee-rate-sat-vb", "2"]
        with redirect_stderr(StringIO()):
            for extra in ([], ["--all", "--amount-sats", "1000"]):
                with self.assertRaises(SystemExit):
                    build_parser().parse_args(base + extra)
        args = build_parser().parse_args(base + ["--all"])
        self.assertTrue(args.all)
        self.assertIsNone(args.amount_sats)

    def test_import_modes_required_and_mutually_exclusive(self):
        base = ["singlekey-importkey", "--wallet-name", "test"]
        with redirect_stderr(StringIO()):
            for extra in ([], ["--wif", "x", "--private-key-hex", "x"]):
                with self.assertRaises(SystemExit):
                    build_parser().parse_args(base + extra)

    def test_cli_dry_run_signed_output_and_no_broadcast(self):
        self.synchronize()
        output = self.directory / "signed.json"
        arguments = ["--network", "testnet4", "singlekey-send", "--wallet-name", "test", "--datadir", str(self.directory),
                     "--from-address-type", "p2wpkh", "--to", self.addresses["p2wpkh"]["address"],
                     "--fee-rate-sat-vb", "2", "--all", "--password", "password", "--cache-only", "--dry-run",
                     "--output-file", str(output)]
        # Fixture filenames deliberately use the main naming style; inject its service.
        with patch("bitcoin_tool._single_key_service", return_value=self.service), redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()):
            run_cli(arguments)
        self.assertTrue(output.exists())
        self.assertIn("transaction was not broadcast", out.getvalue())
        self.assertEqual(self.backend.broadcasts, [])

    def test_saved_transaction_broadcast_uses_single_key_preflight(self):
        from single_key_wallet.storage import write_json
        document = self.prepare(send_all=True)
        output = self.directory / "saved.json"
        write_json(output, document)
        arguments = ["--network", "testnet4", "singlekey-broadcast", "--wallet-name", "test",
                     "--transaction-file", str(output), "--yes"]
        with patch("bitcoin_tool._single_key_service", return_value=self.service), redirect_stdout(StringIO()) as out:
            run_cli(arguments)
        self.assertIn("broadcast accepted:", out.getvalue())
        self.assertEqual(self.backend.broadcasts, [document["hex"]])

    def test_output_file_cannot_overwrite_authoritative_wallet(self):
        original = self.wallet_file.read_bytes()
        arguments = ["--network", "testnet4", "singlekey-send", "--wallet-name", "test", "--from-address-type", "p2wpkh",
                     "--to", self.addresses["p2wpkh"]["address"], "--fee-rate-sat-vb", "2", "--all", "--dry-run",
                     "--output-file", str(self.wallet_file)]
        with patch("bitcoin_tool._single_key_service", return_value=self.service), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            run_cli(arguments)
        self.assertEqual(self.wallet_file.read_bytes(), original)
