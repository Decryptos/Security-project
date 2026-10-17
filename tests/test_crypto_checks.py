import tempfile
from pathlib import Path
from decrypto_crypto_checks import scan_repo_for_crypto_issues


def test_scan_detects_hardcoded_key_assignment():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "vuln.py"
        p.write_text("secret = 'abcdef0123456789abcdef0123456789abcdef012345'\n")
        res = scan_repo_for_crypto_issues(Path(d), ["python"])
        assert res["meta"]["files_inspected"] == 1
        assert res["meta"]["finding_count"] >= 1


def test_scan_detects_pbkdf2_low_iterations():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "hash.py"
        p.write_text("import hashlib\nkey = hashlib.pbkdf2_hmac('sha256', b'p', b'salt', 1000)\n")
        res = scan_repo_for_crypto_issues(Path(d), ["python"])
        assert any(f for f in res["findings"] if f["rule"] == "CRYPTO-PBKDF2" and f["confidence"] == "high")


def test_scan_ignores_non_source_files():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "binary.bin"
        p.write_bytes(b"\x00\x01\x02")
        res = scan_repo_for_crypto_issues(Path(d))
        assert res["meta"]["files_inspected"] == 0
