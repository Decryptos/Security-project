#!/usr/bin/env python3
"""Convenience test runner for Decrypto security project.

Run all unit tests from the tests/ directory.
Usage: python tools/run_tests.py
"""

import sys
import unittest

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
