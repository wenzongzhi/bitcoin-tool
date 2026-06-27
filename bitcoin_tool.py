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
from pathlib import Path
from btc.hash import sha256, dbl_sha256, sha256_file, dbl_sha256_file, show
from btc.private_key_gen import generate_32bytes_private_key, is_valid_privkey
from btc.btc_address_gen import privkey_to_compressed_pubkey, pubkey_to_p2pkh, p2wpkh_bech32_address, p2sh_p2wpkh_address
from version import __version__

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
    try:
        priv = bytes.fromhex(args.privhex)
    except ValueError:
        args.parser.error("invalid hex private key")

    if not is_valid_privkey(priv):
        args.parser.error("invalid private key: must be 32 bytes and 1 <= key < secp256k1_n")
    else:
        pub_c = privkey_to_compressed_pubkey(priv)
        print()
        print("compressed pubkey:", pub_c.hex())

        print("P2PKH (1...):", pubkey_to_p2pkh(pub_c))
        print("P2WPKH (bc1q):", p2wpkh_bech32_address(pub_c))
        print("P2SH-P2WPKH (3...):", p2sh_p2wpkh_address(pub_c))    

"""
def cmd_addr(args):
    priv = bytes.fromhex(args.privhex)
    pub_c = privkey_to_pubkey(priv, compressed=True)
    pub_u = privkey_to_pubkey(priv, compressed=False)

    print("pubkey_compressed  :", pub_c.hex())
    print("pubkey_uncompressed:", pub_u.hex())
    print()

    print("P2PKH (compressed pubkey)  :", p2pkh_address(pub_c, mainnet=not args.testnet))
    print("P2PKH (uncompressed pubkey):", p2pkh_address(pub_u, mainnet=not args.testnet))
    print("P2WPKH (bc1)               :", p2wpkh_address(pub_c, mainnet=not args.testnet))
    print("P2SH-P2WPKH (3...)         :", p2sh_p2wpkh_address(pub_c, mainnet=not args.testnet))
    print()

    scripts = scripts_for_pubkey(pub_c, mainnet=not args.testnet)
    for k, v in scripts.items():
        print(f"{k}: {v}")
"""
def main():
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
    p_addr = sub.add_parser("addr", help="privkey -> pubkey -> addresses + scripts")
    p_addr.add_argument("--privhex", required=True, help="32-byte private key hex (64 hex chars)")
    #p_addr.add_argument("--testnet", action="store_true", help="use testnet version")#to be implemented in future
    p_addr.set_defaults(func=cmd_addr, parser=p_addr)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
