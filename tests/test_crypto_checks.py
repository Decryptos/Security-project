"""Unit tests for decrypto_crypto_checks module."""

import sys
import tempfile
from pathlib import Path

# Add parent directory to path so we can import the modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from decrypto_crypto_checks import scan_repo_for_crypto_issues


def test_scan_detects_hardcoded_key():
    """Test that hardcoded keys are detected."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "vuln.py"
        p.write_text("secret = 'abcdef0123456789abcdef0123456789abcdef012345'\n")
        res = scan_repo_for_crypto_issues(Path(d), ["python"])
        assert res["meta"]["files_inspected"] == 1
        assert res["meta"]["finding_count"] >= 1


def test_scan_ignores_non_source_files():
    """Test that non-source files are ignored."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "binary.bin"
        p.write_bytes(b"\x00\x01\x02")
        res = scan_repo_for_crypto_issues(Path(d))
        assert res["meta"]["files_inspected"] == 0


def test_scan_empty_directory():
    """Test scanning an empty directory."""
    with tempfile.TemporaryDirectory() as d:
        res = scan_repo_for_crypto_issues(Path(d))
        assert len(res["findings"]) == 0
        assert res["meta"]["files_inspected"] == 0


def test_scan_detects_weak_hash():
    """Test that weak hash patterns are detected."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "weak.py"
        p.write_text("import hashlib\nh = hashlib.md5(b'data')")
        res = scan_repo_for_crypto_issues(Path(d))
        assert any(f["rule"] == "CRYPTO-WEAK-HASH" for f in res["findings"])
