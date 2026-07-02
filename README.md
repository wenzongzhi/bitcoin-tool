# Bitcoin tool for study
This is a open source bitcoin tool.
You can use this tool to complete the following task
- Calculate the hash value of any file and any string
- Generate a 32 bytes (256 bit) Bitcoin private key
- Generate compressed/uncompressed public keys and P2PKH addresses from a private key
- Generate P2PKH, P2WPKH, and P2SH-P2WPKH addresses from a compressed public key
- Generate a P2PKH address from an uncompressed public key

## Operating environment
- Python version: 3.12.6, other versions should also work.
- Install dependencies for secp256k1 calculation
```bash
pip install ecdsa
```
```bash
pip install ecdsa bech32
```

## User guide
- generate private key
```bash
$ python bitcoin_tool.py gen
```

- calculate hash value of string
```bash
$ python bitcoin_tool.py hash -s "Satoshi Nakamoto"
```

```bash
$ python bitcoin_tool.py hash -s "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
```

- calculate hash value of file
```bash
$ python bitcoin_tool.py hash -f "E:\github\privatekey\bitcoin.pdf"
```

- generate public key/P2PKH/P2WPKH/P2SH-P2WPKH address 
```bash
$ python bitcoin_tool.py addr --private-key-hex "1415926535897932384626433832795028841971693993751058209749445923"
```

- generate addresses from a compressed or uncompressed public key
```bash
$ python bitcoin_tool.py addr --public-key-hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
```
