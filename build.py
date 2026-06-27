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

from pathlib import Path
import hashlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parent

VERSION_FILE = ROOT / "version_info.txt"
CREATE_ICON = ROOT / "icon" / "create_icon.py"
ICON = ROOT / "icon" / "bitcoin_tool.ico"
ENTRY = ROOT / "bitcoin_tool.py"
EXE = ROOT / "dist" / "bitcoin_tool.exe"
SHA256SUMS = ROOT / "dist" / "SHA256SUMS"

def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
    except Exception:
        return "unknown"

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

try:
    subprocess.check_call([sys.executable, str(CREATE_ICON)])

    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--version-file", str(VERSION_FILE),
        "--onefile",
        "--icon", str(ICON),
        str(ENTRY),
    ])

    commit = git_commit()
    digest = sha256_file(EXE)
    
    SHA256SUMS.write_text(
    f"{digest}  {EXE.name}\ncommit: {commit}\n",
    encoding="utf-8",
)

    print("\nBuild finished successfully.")
    print("Commit:", commit)
    print("SHA256:", digest)

except subprocess.CalledProcessError as e:
    print(f"\nBuild failed: {e}")

except FileNotFoundError as e:
    print(f"\nFile not found: {e}")
    
input("\nPress Enter to exit...")
