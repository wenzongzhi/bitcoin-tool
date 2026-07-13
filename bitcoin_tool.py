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
import shlex
import sys
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
from wallet import (
    WalletError,
    create_wallet,
    default_wallet_file,
    derive_p2wpkh_from_account_xpub,
    export_account_xpub,
    get_mnemonic,
    get_new_address,
    rebuild_address_book,
)

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

    def do_hash(self, argument_line: str) -> None:
        """Hash an ASCII string, hexadecimal string, or file."""
        self._run_command("hash", argument_line)

    def do_gen(self, argument_line: str) -> None:
        """Generate a random 32-byte private key."""
        self._run_command("gen", argument_line)

    def do_addr(self, argument_line: str) -> None:
        """Generate Bitcoin addresses from a private or public key."""
        self._run_command("addr", argument_line)

    def do_createwallet(self, argument_line: str) -> None:
        """Create a BIP84 wallet."""
        self._run_command("createwallet", argument_line)

    def do_getnewaddress(self, argument_line: str) -> None:
        """Derive the next wallet address."""
        self._run_command("getnewaddress", argument_line)

    def do_getmnemonic(self, argument_line: str) -> None:
        """Decrypt and display a wallet mnemonic."""
        self._run_command("getmnemonic", argument_line)

    def do_rebuildaddressbook(self, argument_line: str) -> None:
        """Rebuild wallet address metadata."""
        self._run_command("rebuildaddressbook", argument_line)

    def do_exportxpub(self, argument_line: str) -> None:
        """Export a wallet account xpub."""
        self._run_command("exportxpub", argument_line)

    def do_derivepub(self, argument_line: str) -> None:
        """Derive an address from an account xpub."""
        self._run_command("derivepub", argument_line)

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
    p_createwallet.add_argument(
        "--entropy-hex",
        help="optional 256-bit entropy (64 hex characters)",
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
        help="decrypt and display an encrypted wallet mnemonic",
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
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

def main() -> None:
    run_cli()

if __name__ == "__main__":
    main()
