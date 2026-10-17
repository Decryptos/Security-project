import tempfile
from pathlib import Path
from decrypto_crypto_checks import scan_repo_for_crypto_issues


def test_scan_detects_hardcoded_key():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "vuln.py"
        p.write_text("secret = 'abcdef0123456789abcdef0123456789abcdef012345'\n")
        res = scan_repo_for_crypto_issues(Path(d), ["python"])
        assert res["meta"]["files_inspected"] == 1
        assert res["meta"]["finding_count"] >= 1


def test_scan_ignores_non_source_files():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "binary.bin"
        p.write_bytes(b"\x00\x01\x02")
        res = scan_repo_for_crypto_issues(Path(d))
        assert res["meta"]["files_inspected"] == 0
