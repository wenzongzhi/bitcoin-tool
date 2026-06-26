## Operating environment
- Install dependencies for creating the icon file, if you want to compile this tool to exe file
```bash
python -m pip install pillow
```
```bash
python create_icon.py
```
```bash
pyinstaller --onefile --icon icon/bitcoin_tool.ico bitcoin_tool.py
```