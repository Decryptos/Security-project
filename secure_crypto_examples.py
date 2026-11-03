#!/usr/bin/env python3
"""Secure crypto examples in Python.

This module provides safe, Python-native examples for use in a crypto-aware codebase.
It demonstrates secure random generation and password-based key derivation using the
Python standard library without depending on JavaScript.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_random_bytes(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes."""
    if length <= 0:
        raise ValueError("length must be positive")
    return secrets.token_bytes(length)


def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a key using PBKDF2-HMAC-SHA256 with a high iteration count."""
    if iterations < 100_000:
        raise ValueError("iterations should be at least 100000 for password-based KDFs")
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes-like")
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", password_bytes, bytes(salt), iterations)


def compute_hmac(message: bytes, key: bytes) -> bytes:
    """Compute a keyed HMAC for integrity verification."""
    return hmac.new(key, message, hashlib.sha256).digest()


def secure_compare(left: bytes, right: bytes) -> bool:
    """Compare secret values using constant-time comparison."""
    return hmac.compare_digest(left, right)


def main() -> None:
    salt = generate_random_bytes(16)
    password = "correct horse battery staple"
    derived = derive_key_from_password(password, salt)
    digest = compute_hmac(b"hello", derived)
    print({
        "salt_hex": salt.hex(),
        "derived_key_hex": derived.hex(),
        "hmac_hex": digest.hex(),
    })


if __name__ == "__main__":
    main()
