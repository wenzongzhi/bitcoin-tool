# Asset attribution

The Bitcoin logo used by this project is based on the standard
Bitcoin logo distributed through Wikimedia Commons.

Source:  
https://commons.wikimedia.org/wiki/File:Bitcoin.svg

Wikimedia Commons identifies the referenced logo as being in the
public domain because it does not meet the threshold of originality
required for copyright protection.

Bitcoin and the Bitcoin logo may be subject to trademark or other
rights in some jurisdictions.

This project is an independent open-source project and is not
affiliated with or endorsed by Bitcoin Core developers or
bitcoin.org.

# Icon build instructions

Install Pillow if you want to regenerate the application icon:

```bash
python -m pip install Pillow
```

Generate the icon file:

```bash
python create_icon.py
```

Build the standalone executable with PyInstaller:

```bash
pyinstaller --onefile --icon icon/bitcoin_tool.ico bitcoin_tool.py
```