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
from version import __version__

ROOT = Path(__file__).resolve().parent

CREATE_ICON = ROOT / "icon" / "create_icon.py"
ICON = ROOT / "icon" / "bitcoin_tool.ico"
ENTRY = ROOT / "bitcoin_tool.py"
EXE = ROOT / "dist" / "bitcoin_tool.exe"
SHA256SUMS = ROOT / "dist" / "SHA256SUMS"
COMMIT_INFO = ROOT / "dist" / "BUILD_INFO.txt"

VERSION_TEMPLATE = ROOT / "version_info.template"
VERSION_FILE = ROOT / "build" / "version_info.txt"

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

def version_tuple(version: str) -> tuple[int, int, int, int]:
    try:
        parts = [int(x) for x in version.split(".")]
    except ValueError:
        raise ValueError(
            f"Invalid version '{version}', expected format like '0.1.0'"
        )
    return tuple((parts + [0, 0, 0, 0])[:4])

def write_version_info():
    VERSION_FILE.parent.mkdir(exist_ok=True)

    v = version_tuple(__version__)

    text = VERSION_TEMPLATE.read_text(encoding="utf-8").format(
        filevers=v,
        prodvers=v,
        version=__version__,
    )

    VERSION_FILE.write_text(text, encoding="utf-8")

try:
    subprocess.check_call([sys.executable, str(CREATE_ICON)], cwd=ROOT)
    
    write_version_info()
    
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--version-file", str(VERSION_FILE),
        "--onefile",
        "--icon", str(ICON),
        str(ENTRY),
    ], cwd=ROOT)

    commit = git_commit()
    digest = sha256_file(EXE)
    
    SHA256SUMS.write_text(
        f"{digest}  {EXE.name}\n",
        encoding="utf-8",
    )

    COMMIT_INFO.write_text(
        f"commit: {commit}\n",
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
