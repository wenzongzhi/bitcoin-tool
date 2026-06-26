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
import subprocess
import sys

ROOT = Path(__file__).resolve().parent

try:
    subprocess.check_call([sys.executable, str(ROOT / "icon" / "create_icon.py")])

    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--onefile",
        "--icon", str(ROOT / "icon" / "bitcoin_tool.ico"),
        "bitcoin_tool.py",
    ])

    print("\nBuild finished successfully.")

except subprocess.CalledProcessError as e:
    print(f"\nBuild failed: {e}")

input("\nPress Enter to exit...")