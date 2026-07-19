"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import cmd
import re
import shlex
import sys
from functools import lru_cache
from pathlib import Path
from btc.hash import sha256, dbl_sha256, sha256_file, dbl_sha256_file, show
from btc.private_key_gen import generate_32bytes_private_key, is_valid_privkey
from btc.btc_address_gen import (
    is_valid_public_key,
    privkey_to_pubkey,
    public_key_to_compressed,
    pubkey_to_p2pkh,
    p2tr_address,
    p2wpkh_bech32_address,
    p2sh_p2wpkh_address,
)
from version import __version__
from network import EsploraBackend, EsploraError
from wallet import (
    WalletError,
    create_wallet,
    default_wallet_cache_file,
    default_wallet_file,
    derive_p2wpkh_from_account_xpub,
    export_account_xpub,
    entropy_hex_from_mnemonic,
    get_cached_balance,
    get_mnemonic,
    get_new_address,
    list_cached_transactions,
    list_cached_unspent,
    mnemonic_from_entropy_hex,
    rebuild_address_book,
    sync_wallet,
)

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.styles import Style
except ImportError:
    PromptSession = None
    Completer = object
    Completion = None
    HTML = None
    Lexer = object
    Style = None


def cmd_hash(args):
    parser = args.parser
    
    if args.string is not None:
        data = args.string.encode("utf-8")
        print("input:", repr(args.string))
        print()
        show("SHA256", sha256(data))
        show("Double-SHA256", dbl_sha256(data))
        return
    elif args.hex is not None:
        try: 
            data = bytes.fromhex(args.hex)
        except ValueError:
            parser.error(f'invalid hex string: "{args.hex}"')
        print("input:", repr(args.hex))
        print()
        show("SHA256", sha256(data))
        show("Double-SHA256", dbl_sha256(data))
        return
    else:
        file_path = Path(args.file).expanduser().resolve()
        if not file_path.exists():
            #raise FileNotFoundError(f"File not found: {file_path}")
            parser.error(f'file not found: "{file_path}"')
        if not file_path.is_file():
            #raise ValueError(f"Not a file: {file_path}")
            parser.error(f'not a file: "{file_path}"')
            
        file_path = file_path.resolve()
        h1 = sha256_file(file_path)
        h2 = dbl_sha256_file(file_path)
        print("file:", file_path)
        print("SHA256(file)      =", h1.hex())
        print("Double-SHA256(file)=", h2.hex())

def cmd_gen(args):
    key_bytes, key_hex = generate_32bytes_private_key()
    print()

    print("32 Bytes original private number:   ", key_bytes)
    print(f"32 Bytes Hex private key:   ", key_hex)
    
def cmd_addr(args):
    if args.private_key_hex is not None:
        try:
            priv = bytes.fromhex(args.private_key_hex)
        except ValueError:
            args.parser.error("invalid hex private key")

        if not is_valid_privkey(priv):
            args.parser.error("invalid private key: must be 32 bytes and 1 <= key < secp256k1_n")

        pub_c = privkey_to_pubkey(priv, compressed=True)
        pub_u = privkey_to_pubkey(priv, compressed=False)
        print("compressed pubkey  :", pub_c.hex())
        print("uncompressed pubkey:", pub_u.hex())
        print()
        print("P2PKH (compressed pubkey)  :", pubkey_to_p2pkh(pub_c))
        print("P2PKH (uncompressed pubkey):", pubkey_to_p2pkh(pub_u))
        print("P2WPKH (bc1q)              :", p2wpkh_bech32_address(pub_c))
        print("P2SH-P2WPKH (3...)         :", p2sh_p2wpkh_address(pub_c))
        print("P2TR (bc1p)                :", p2tr_address(pub_c))
        return

    try:
        pubkey = bytes.fromhex(args.public_key_hex)
    except ValueError:
        args.parser.error("invalid hex public key")

    if not is_valid_public_key(pubkey):
        args.parser.error(
            "invalid public key: expected a compressed (33-byte) or "
            "uncompressed (65-byte) secp256k1 public key"
        )

    compressed = len(pubkey) == 33
    pub_c = public_key_to_compressed(pubkey)
    print("input public key type        :", "compressed" if compressed else "uncompressed")
    if not compressed:
        print("P2PKH (uncompressed pubkey)  :", pubkey_to_p2pkh(pubkey))
    print("compressed pubkey            :", pub_c.hex())
    print("P2PKH (compressed pubkey)    :", pubkey_to_p2pkh(pub_c))
    print("P2WPKH (bc1q)                :", p2wpkh_bech32_address(pub_c))
    print("P2SH-P2WPKH (3...)           :", p2sh_p2wpkh_address(pub_c))
    print("P2TR (bc1p)                  :", p2tr_address(pub_c))


def cmd_createwallet(args):
    try:
        result = create_wallet(
            wallet_name=args.wallet_name,
            password=args.password,
            entropy_hex=args.entropy_hex,
            mnemonic=args.mnemonic,
            wallet_file=default_wallet_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    if not result["encrypted"]:
        print(
            "WARNING: mnemonic is stored without encryption. "
            "This is dangerous and intended for experiments only.",
            file=sys.stderr,
        )
    print("wallet name :", result["wallet_name"])
    if result["mnemonic"] is not None:
        print("mnemonic    :", result["mnemonic"])
    print("encrypted   :", "yes" if result["encrypted"] else "no")
    print("wallet file :", result["wallet_file"])


def cmd_convert(args):
    try:
        if args.entropy_hex is not None:
            mnemonic = mnemonic_from_entropy_hex(args.entropy_hex)
            print("entropy hex :", args.entropy_hex.lower())
            print("mnemonic    :", mnemonic)
        else:
            entropy_hex = entropy_hex_from_mnemonic(args.mnemonic)
            print("mnemonic    :", " ".join(args.mnemonic.strip().split()))
            print("entropy hex :", entropy_hex)
    except WalletError as exc:
        args.parser.error(str(exc))


def cmd_getnewaddress(args):
    try:
        result = get_new_address(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir),
            change=args.change,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name     :", result["wallet_name"])
    print("address         :", result["address"])
    print("address type    :", result["address_type"])
    print("address purpose :", result["purpose"])
    print("branch          :", result["branch"])
    print("address index   :", result["index"])
    print("relative path   :", result["relative_derivation_path"])
    print("derivation path :", result["derivation_path"])


def cmd_getmnemonic(args):
    try:
        result = get_mnemonic(
            wallet_name=args.wallet_name,
            password=args.password,
            wallet_file=default_wallet_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name :", result["wallet_name"])
    print("mnemonic    :", result["mnemonic"])


def cmd_rebuildaddressbook(args):
    try:
        result = rebuild_address_book(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name       :", result["wallet_name"])
    print("address count     :", result["address_count"])
    print("recovered entries :", result["recovered_count"])
    print("wallet file       :", result["wallet_file"])


def cmd_exportxpub(args):
    try:
        result = export_account_xpub(
            wallet_name=args.wallet_name,
            password=args.password,
            wallet_file=default_wallet_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name     :", result["wallet_name"])
    print("address type    :", result["address_type"])
    print("account path    :", result["account_derivation_path"])
    print("account xpub    :", result["account_xpub"])
    print("descriptor-like :", result["descriptor_like"])


def cmd_derivepub(args):
    try:
        if args.type.lower() != "p2wpkh":
            args.parser.error("only p2wpkh derivation is currently supported")
        address = derive_p2wpkh_from_account_xpub(
            args.xpub,
            args.branch,
            args.index,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("address type :", "P2WPKH")
    print("branch       :", args.branch)
    print("index        :", args.index)
    print("relative path:", f"m/{args.branch}/{args.index}")
    print("address      :", address)


def _format_btc(satoshis: int) -> str:
    return f"{satoshis / 100_000_000:.8f} BTC"


def cmd_syncwallet(args):
    try:
        result = sync_wallet(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir),
            cache_file=default_wallet_cache_file(args.datadir),
            backend=EsploraBackend(args.backend_url, args.timeout),
            include_transactions=not args.no_transactions,
        )
    except (WalletError, EsploraError) as exc:
        args.parser.error(str(exc))

    balance = result["balance"]
    print("wallet name        :", result["wallet_name"])
    print("synced at          :", result["synced_at"])
    print("backend            :", result["backend"]["base_url"])
    print("tip height         :", result["tip"]["height"])
    print("tip hash           :", result["tip"]["hash"])
    print("address count      :", result["address_count"])
    print("used address count :", result["used_address_count"])
    print("utxo count         :", len(result["utxos"]))
    print("transaction count  :", len(result["transactions"]))
    print("confirmed balance  :", balance["confirmed"], "sats", f"({_format_btc(balance['confirmed'])})")
    print("unconfirmed balance:", balance["unconfirmed"], "sats", f"({_format_btc(balance['unconfirmed'])})")
    print("total balance      :", balance["total"], "sats", f"({_format_btc(balance['total'])})")
    print("cache file         :", result["cache_file"])


def cmd_getbalance(args):
    try:
        result = get_cached_balance(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    balance = result["balance"]
    print("wallet name        :", result["wallet_name"])
    print("synced at          :", result["synced_at"])
    print("tip height         :", result.get("tip", {}).get("height"))
    print("confirmed balance  :", balance["confirmed"], "sats", f"({_format_btc(balance['confirmed'])})")
    print("unconfirmed balance:", balance["unconfirmed"], "sats", f"({_format_btc(balance['unconfirmed'])})")
    print("total balance      :", balance["total"], "sats", f"({_format_btc(balance['total'])})")
    print("cache file         :", result["cache_file"])


def cmd_listunspent(args):
    if args.min_confirmations < 0:
        args.parser.error("--min-confirmations must not be negative")
    try:
        result = list_cached_unspent(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    min_confirmations = args.min_confirmations
    utxos = [
        utxo
        for utxo in result["utxos"]
        if int(utxo.get("confirmations", 0)) >= min_confirmations
    ]
    print("wallet name :", result["wallet_name"])
    print("synced at   :", result["synced_at"])
    print("utxo count  :", len(utxos))
    for utxo in utxos:
        print()
        print("txid         :", utxo["txid"])
        print("vout         :", utxo["vout"])
        print("value        :", utxo["value"], "sats", f"({_format_btc(utxo['value'])})")
        print("confirmed    :", "yes" if utxo.get("confirmed") else "no")
        print("confirmations:", utxo.get("confirmations", 0))
        print("address      :", utxo["address"])
        print("path         :", utxo["path"])
        print("scriptPubKey :", utxo["script_pubkey"])


def cmd_listtransactions(args):
    if args.limit < 0:
        args.parser.error("--limit must not be negative")
    try:
        result = list_cached_transactions(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir),
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    transactions = result["transactions"][: args.limit]
    print("wallet name        :", result["wallet_name"])
    print("synced at          :", result["synced_at"])
    print("transaction count  :", len(result["transactions"]))
    print("displayed count    :", len(transactions))
    print("complete history   :", "yes" if result["transactions_complete"] else "no")
    for tx in transactions:
        print()
        print("txid         :", tx["txid"])
        print("direction    :", tx["direction"])
        print("net          :", tx["net"], "sats", f"({_format_btc(tx['net'])})")
        print("received     :", tx["received"], "sats", f"({_format_btc(tx['received'])})")
        print("sent         :", tx["sent"], "sats", f"({_format_btc(tx['sent'])})")
        print("fee          :", tx["fee"], "sats", f"({_format_btc(tx['fee'])})")
        print("confirmed    :", "yes" if tx.get("confirmed") else "no")
        print("confirmations:", tx.get("confirmations", 0))
        print("addresses    :", ", ".join(tx.get("addresses", [])))


SHELL_BUILTIN_COMMANDS = {
    "exit": "Exit the interactive shell.",
    "quit": "Exit the interactive shell.",
    "help": "Show shell or command help.",
}


def _find_subparsers_action(parser: argparse.ArgumentParser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


@lru_cache(maxsize=1)
def _shell_completion_index() -> tuple[dict[str, argparse.ArgumentParser], dict[str, list[str]]]:
    parser = build_parser()
    subparsers_action = _find_subparsers_action(parser)
    if subparsers_action is None:
        return {}, {}

    command_parsers = dict(subparsers_action.choices)
    options_by_command = {}
    for command, command_parser in command_parsers.items():
        options = []
        for action in command_parser._actions:
            if action.help == argparse.SUPPRESS:
                continue
            options.extend(action.option_strings)
        options_by_command[command] = sorted(options)
    return command_parsers, options_by_command


def _split_completion_arguments(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return text.split()


def _current_completion_prefix(text_before_cursor: str) -> str:
    if not text_before_cursor or text_before_cursor[-1].isspace():
        return ""
    return text_before_cursor.rsplit(maxsplit=1)[-1]


def _shell_option_matches(command: str, prefix: str) -> list[str]:
    _, options_by_command = _shell_completion_index()
    return [
        option
        for option in options_by_command.get(command, [])
        if option.startswith(prefix)
    ]


def _shell_command_matches(prefix: str) -> list[str]:
    command_parsers, _ = _shell_completion_index()
    commands = sorted(
        [
            command
            for command in [*command_parsers, *SHELL_BUILTIN_COMMANDS]
            if command != "shell"
        ]
    )
    return [command for command in commands if command.startswith(prefix)]


def _print_shell_help(command: str | None = None) -> None:
    command_parsers, _ = _shell_completion_index()
    if command:
        if command in command_parsers:
            command_parsers[command].print_help()
            return
        if command in SHELL_BUILTIN_COMMANDS:
            print(f"{command}: {SHELL_BUILTIN_COMMANDS[command]}")
            return
        print(f'unknown command: "{command}"', file=sys.stderr)
        return

    print("Available commands:")
    help_by_command = {}
    subparser_action = _find_subparsers_action(build_parser())
    if subparser_action is not None:
        help_by_command = {
            choice_action.dest: choice_action.help
            for choice_action in subparser_action._choices_actions
        }
    for name in sorted(command for command in command_parsers if command != "shell"):
        print(f"  {name:<20} {help_by_command.get(name, '')}")
    for name, help_text in SHELL_BUILTIN_COMMANDS.items():
        print(f"  {name:<20} {help_text}")
    print('\nUse "help <command>" for command-specific options.')


class BitcoinToolCompleter(Completer):
    def get_completions(self, document, complete_event):
        text_before_cursor = document.text_before_cursor
        stripped = text_before_cursor.lstrip()
        prefix = _current_completion_prefix(text_before_cursor)
        words = _split_completion_arguments(stripped)

        completing_first_token = (
            not words
            or (len(words) == 1 and not text_before_cursor[-1:].isspace())
        )
        if completing_first_token:
            for command in _shell_command_matches(prefix):
                yield Completion(command, start_position=-len(prefix))
            return

        command = words[0]
        if command == "help":
            for candidate in _shell_command_matches(prefix):
                yield Completion(candidate, start_position=-len(prefix))
            return

        for option in _shell_option_matches(command, prefix):
            yield Completion(option, start_position=-len(prefix))


class BitcoinToolLexer(Lexer):
    _token_pattern = re.compile(r"\s+|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|\S+")
    _hex_pattern = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
    _number_pattern = re.compile(r"\d+")

    def lex_document(self, document):
        command_parsers, _ = _shell_completion_index()

        def get_line(lineno: int):
            try:
                line = document.lines[lineno]
            except IndexError:
                return []

            fragments = []
            command_seen = False
            for match in self._token_pattern.finditer(line):
                token = match.group(0)
                if token.isspace():
                    fragments.append(("", token))
                    continue

                if not command_seen:
                    style = (
                        "class:command"
                        if token in command_parsers or token in SHELL_BUILTIN_COMMANDS
                        else "class:error"
                    )
                    command_seen = True
                elif token.startswith("-"):
                    style = "class:option"
                elif token.startswith(("\"", "'")):
                    style = "class:string"
                elif self._number_pattern.fullmatch(token):
                    style = "class:number"
                elif self._hex_pattern.fullmatch(token):
                    style = "class:hex"
                else:
                    style = "class:value"
                fragments.append((style, token))
            return fragments

        return get_line


def _run_prompt_toolkit_shell() -> None:
    style = Style.from_dict(
        {
            "prompt": "ansigreen bold",
            "command": "ansicyan bold",
            "option": "ansigreen",
            "string": "ansiblue",
            "number": "ansiyellow",
            "hex": "ansimagenta",
            "value": "ansiwhite",
            "error": "ansired",
        }
    )
    session = PromptSession(
        lexer=BitcoinToolLexer(),
        completer=BitcoinToolCompleter(),
        complete_while_typing=True,
        style=style,
    )
    print("Bitcoin Tool interactive shell")
    print("Powered by Wen Zhongzhi")
    print('Type "help" to show commands and "exit" to quit.')

    while True:
        try:
            command_line = session.prompt(HTML("<prompt>bitcoin-tool&gt; </prompt>"))
        except (EOFError, KeyboardInterrupt):
            print()
            break

        stripped = command_line.strip()
        if not stripped:
            continue

        arguments = _split_shell_arguments(stripped)
        if arguments is None:
            continue

        command = arguments[0]
        command_arguments = arguments[1:]
        if command in {"exit", "quit"}:
            break
        if command == "help":
            _print_shell_help(command_arguments[0] if command_arguments else None)
            continue
        if command == "shell":
            print("already in interactive shell", file=sys.stderr)
            continue

        try:
            run_cli([command, *command_arguments])
        except SystemExit:
            pass


def _split_shell_arguments(argument_line: str) -> list[str] | None:
    """
    Split an interactive command line into argparse-compatible arguments.

    posix=False is used so Windows paths such as D:\\wallets are not
    interpreted as strings containing escape characters.
    """
    try:
        arguments = shlex.split(argument_line, posix=False)
    except ValueError as exc:
        print(f"invalid command line: {exc}", file=sys.stderr)
        return None

    # With posix=False, shlex preserves surrounding quotation marks.
    # Remove one pair so argparse receives my_BTC_001 instead of
    # "my_BTC_001".
    normalized_arguments = []

    for argument in arguments:
        if (
            len(argument) >= 2
            and argument[0] == argument[-1]
            and argument[0] in {'"', "'"}
        ):
            argument = argument[1:-1]

        normalized_arguments.append(argument)

    return normalized_arguments


class BitcoinToolShell(cmd.Cmd):
    intro = (
        "Bitcoin Tool interactive shell\n"
        "Powered by Wen Zhongzhi\n"
        'Type "help" to show commands and "exit" to quit.'
    )
    prompt = "bitcoin-tool> "

    def emptyline(self) -> None:
        # cmd.Cmd normally repeats the previous command on an empty line.
        # For a wallet tool, doing nothing is safer.
        pass

    def _run_command(self, command: str, argument_line: str) -> None:
        arguments = _split_shell_arguments(argument_line)

        if arguments is None:
            return

        try:
            run_cli([command, *arguments])
        except SystemExit:
            # argparse uses SystemExit for --help and argument errors.
            # Do not exit the interactive shell.
            pass

    def _complete_options(self, command: str, text: str) -> list[str]:
        return _shell_option_matches(command, text)

    def completenames(self, text: str, *ignored) -> list[str]:
        return [f"{command} " for command in _shell_command_matches(text)]

    def do_help(self, argument_line: str) -> None:
        arguments = _split_shell_arguments(argument_line)
        if arguments is None:
            return
        _print_shell_help(arguments[0] if arguments else None)

    def do_hash(self, argument_line: str) -> None:
        """Hash an ASCII string, hexadecimal string, or file."""
        self._run_command("hash", argument_line)

    def complete_hash(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("hash", text)

    def do_gen(self, argument_line: str) -> None:
        """Generate a random 32-byte private key."""
        self._run_command("gen", argument_line)

    def do_addr(self, argument_line: str) -> None:
        """Generate Bitcoin addresses from a private or public key."""
        self._run_command("addr", argument_line)

    def complete_addr(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("addr", text)

    def do_createwallet(self, argument_line: str) -> None:
        """Create a BIP84 wallet."""
        self._run_command("createwallet", argument_line)

    def complete_createwallet(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("createwallet", text)

    def do_convert(self, argument_line: str) -> None:
        """Convert between BIP39 entropy and mnemonic."""
        self._run_command("convert", argument_line)

    def complete_convert(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("convert", text)

    def do_getnewaddress(self, argument_line: str) -> None:
        """Derive the next wallet address."""
        self._run_command("getnewaddress", argument_line)

    def complete_getnewaddress(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getnewaddress", text)

    def do_getmnemonic(self, argument_line: str) -> None:
        """Display a wallet mnemonic."""
        self._run_command("getmnemonic", argument_line)

    def complete_getmnemonic(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getmnemonic", text)

    def do_rebuildaddressbook(self, argument_line: str) -> None:
        """Rebuild wallet address metadata."""
        self._run_command("rebuildaddressbook", argument_line)

    def complete_rebuildaddressbook(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("rebuildaddressbook", text)

    def do_exportxpub(self, argument_line: str) -> None:
        """Export a wallet account xpub."""
        self._run_command("exportxpub", argument_line)

    def complete_exportxpub(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("exportxpub", text)

    def do_derivepub(self, argument_line: str) -> None:
        """Derive an address from an account xpub."""
        self._run_command("derivepub", argument_line)

    def complete_derivepub(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("derivepub", text)

    def do_syncwallet(self, argument_line: str) -> None:
        """Sync wallet chain state into the local cache."""
        self._run_command("syncwallet", argument_line)

    def complete_syncwallet(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("syncwallet", text)

    def do_getbalance(self, argument_line: str) -> None:
        """Read wallet balance from the local cache."""
        self._run_command("getbalance", argument_line)

    def complete_getbalance(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getbalance", text)

    def do_listunspent(self, argument_line: str) -> None:
        """List cached wallet UTXOs."""
        self._run_command("listunspent", argument_line)

    def complete_listunspent(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("listunspent", text)

    def do_listtransactions(self, argument_line: str) -> None:
        """List cached wallet transactions."""
        self._run_command("listtransactions", argument_line)

    def complete_listtransactions(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("listtransactions", text)

    def do_exit(self, argument_line: str) -> bool:
        """Exit the interactive shell."""
        return True

    def do_quit(self, argument_line: str) -> bool:
        """Exit the interactive shell."""
        return True

    def do_EOF(self, argument_line: str) -> bool:
        """Exit when Ctrl+Z followed by Enter is entered on Windows."""
        print()
        return True

def cmd_shell(args) -> None:
    if PromptSession is not None:
        _run_prompt_toolkit_shell()
    else:
        BitcoinToolShell().cmdloop()

def add_wallet_access_arguments(parser):
    parser.add_argument("--wallet-name", required=True, help="wallet name")
    parser.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bitcoin_tool",
        description="Bitcoin research CLI tool: hash / keys / address / scripts"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    sub = parser.add_subparsers(dest="cmd", required=True)

    # hash
    p_hash = sub.add_parser("hash", help="hash a ASCII string, hex string or a file")
    g = p_hash.add_mutually_exclusive_group(required=True)
    g.add_argument("-s", "--string", help="input ASCII string")
    g.add_argument("-x", "--hex", help="input hex string")
    g.add_argument("-f", "--file", help="input file path")

    p_hash.set_defaults(func=cmd_hash, parser=p_hash)

    # gen
    p_gen = sub.add_parser("gen", help="generate random 32-byte private key")
    p_gen.set_defaults(func=cmd_gen)

    # convert
    p_convert = sub.add_parser(
        "convert",
        help="convert between BIP39 entropy hex and mnemonic words",
    )
    convert_input = p_convert.add_mutually_exclusive_group(required=True)
    convert_input.add_argument(
        "--entropy-hex-to-mnemonic",
        dest="entropy_hex",
        help="BIP39 entropy hex: 128, 160, 192, 224, or 256 bits",
    )
    convert_input.add_argument(
        "--mnemonic-to-entropy-hex",
        dest="mnemonic",
        help="BIP39 mnemonic words",
    )
    p_convert.set_defaults(func=cmd_convert, parser=p_convert)
    
    # addr
    p_addr = sub.add_parser("addr", help="private/public key -> Bitcoin addresses")
    addr_input = p_addr.add_mutually_exclusive_group(required=True)
    addr_input.add_argument(
        "--private-key-hex",
        help="32-byte private key hex (64 hex chars)",
    )
    addr_input.add_argument(
        "--public-key-hex",
        help="compressed (33-byte) or uncompressed (65-byte) public key hex",
    )
    #p_addr.add_argument("--testnet", action="store_true", help="use testnet version")#to be implemented in future
    p_addr.set_defaults(func=cmd_addr, parser=p_addr)

    # createwallet
    p_createwallet = sub.add_parser("createwallet", help="create a BIP84 wallet")
    p_createwallet.add_argument(
        "--wallet-name",
        required=True,
        help="wallet name (letters, numbers, underscores, and hyphens)",
    )
    wallet_seed_input = p_createwallet.add_mutually_exclusive_group()
    wallet_seed_input.add_argument(
        "--entropy-hex",
        help="optional 256-bit entropy (64 hex characters)",
    )
    wallet_seed_input.add_argument(
        "--mnemonic",
        help="import BIP39 mnemonic words",
    )
    p_createwallet.add_argument(
        "--password",
        help="encrypt the mnemonic with AES-256-GCM",
    )
    p_createwallet.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_createwallet.set_defaults(func=cmd_createwallet, parser=p_createwallet)

    # getnewaddress
    p_getnewaddress = sub.add_parser(
        "getnewaddress",
        help="derive the next P2WPKH receiving address",
    )
    add_wallet_access_arguments(p_getnewaddress)
    p_getnewaddress.add_argument(
        "--change",
        action="store_true",
        help="derive the next P2WPKH change address instead of a receiving address",
    )
    p_getnewaddress.set_defaults(func=cmd_getnewaddress, parser=p_getnewaddress)

    # getmnemonic
    p_getmnemonic = sub.add_parser(
        "getmnemonic",
        help="display a wallet mnemonic; encrypted wallets require a password",
    )
    p_getmnemonic.add_argument("--wallet-name", required=True, help="wallet name")
    p_getmnemonic.add_argument(
        "--password",
        help="password for an encrypted wallet",
    )
    p_getmnemonic.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_getmnemonic.set_defaults(func=cmd_getmnemonic, parser=p_getmnemonic)

    # rebuildaddressbook
    p_rebuildaddressbook = sub.add_parser(
        "rebuildaddressbook",
        help="rebuild issued address metadata from wallet public derivation state",
    )
    add_wallet_access_arguments(p_rebuildaddressbook)
    p_rebuildaddressbook.set_defaults(
        func=cmd_rebuildaddressbook,
        parser=p_rebuildaddressbook,
    )

    # exportxpub
    p_exportxpub = sub.add_parser(
        "exportxpub",
        help="export the BIP84 account xpub for a wallet",
    )
    p_exportxpub.add_argument("--wallet-name", required=True, help="wallet name")
    p_exportxpub.add_argument(
        "--password",
        help="password for an encrypted wallet",
    )
    p_exportxpub.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_exportxpub.set_defaults(func=cmd_exportxpub, parser=p_exportxpub)

    # derivepub
    p_derivepub = sub.add_parser(
        "derivepub",
        help="derive a P2WPKH address from an account xpub",
    )
    p_derivepub.add_argument("--xpub", required=True, help="account xpub")
    p_derivepub.add_argument(
        "--type",
        default="p2wpkh",
        choices=["p2wpkh"],
        help="address type",
    )
    p_derivepub.add_argument(
        "--branch",
        type=int,
        default=0,
        choices=[0, 1],
        help="0 for receiving addresses, 1 for change addresses",
    )
    p_derivepub.add_argument("--index", type=int, required=True)
    p_derivepub.set_defaults(func=cmd_derivepub, parser=p_derivepub)

    # syncwallet
    p_syncwallet = sub.add_parser(
        "syncwallet",
        help="sync wallet UTXOs and transactions into the local cache",
    )
    add_wallet_access_arguments(p_syncwallet)
    p_syncwallet.add_argument(
        "--backend-url",
        default="https://blockstream.info/api",
        help="Esplora API base URL",
    )
    p_syncwallet.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="network timeout in seconds",
    )
    p_syncwallet.add_argument(
        "--no-transactions",
        action="store_true",
        help="skip transaction history and sync only address stats and UTXOs",
    )
    p_syncwallet.set_defaults(func=cmd_syncwallet, parser=p_syncwallet)

    # getbalance
    p_getbalance = sub.add_parser(
        "getbalance",
        help="read wallet balance from the local cache",
    )
    add_wallet_access_arguments(p_getbalance)
    p_getbalance.set_defaults(func=cmd_getbalance, parser=p_getbalance)

    # listunspent
    p_listunspent = sub.add_parser(
        "listunspent",
        help="list cached wallet UTXOs",
    )
    add_wallet_access_arguments(p_listunspent)
    p_listunspent.add_argument(
        "--min-confirmations",
        type=int,
        default=0,
        help="minimum number of confirmations to display",
    )
    p_listunspent.set_defaults(func=cmd_listunspent, parser=p_listunspent)

    # listtransactions
    p_listtransactions = sub.add_parser(
        "listtransactions",
        help="list cached wallet transactions",
    )
    add_wallet_access_arguments(p_listtransactions)
    p_listtransactions.add_argument(
        "--limit",
        type=int,
        default=20,
        help="maximum number of transactions to display",
    )
    p_listtransactions.set_defaults(func=cmd_listtransactions, parser=p_listtransactions)

    # shell
    p_shell = sub.add_parser(
        "shell",
        help="start the interactive shell with command completion",
    )
    p_shell.set_defaults(
        func=cmd_shell,
        parser=p_shell,
    )

    return parser

def run_cli(argv: list[str] | None = None) -> None:    
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        argv = ["shell"]
        
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

def main() -> None:
    run_cli()

if __name__ == "__main__":
    main()
