import ast
from pathlib import Path
import subprocess
import sys
import unittest


class IsolationTest(unittest.TestCase):
    def test_no_hd_imports_even_transitively(self):
        directory = Path(__file__).resolve().parents[1]
        for path in directory.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [v.name for v in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [node.module or ""]
                else:
                    continue
                for module in modules:
                    self.assertFalse(module == "wallet" or module.startswith("wallet."), str(path))
        result = subprocess.run(
            [sys.executable, "-c", "import single_key_wallet, sys; assert not any(m == 'wallet' or m.startswith('wallet.') for m in sys.modules)"],
            cwd=directory.parent, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
