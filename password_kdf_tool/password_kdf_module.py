"""
Production-ready password-based key derivation and hashing module.

This module provides:
- PBKDF2-HMAC-SHA256 key derivation
- scrypt key derivation
- bcrypt password hashing and verification
- Password strength analysis with recommendations

Security notes:
- Defaults follow OWASP-aligned guidance and prioritize security over speed.
- Password bytes are handled in memory as required by Python APIs; Python does not
  guarantee secure memory zeroization for immutable strings/bytes.
- Use HTTPS/TLS and secure storage for all derived keys and password hashes.
"""

from __future__ import annotations

import math
import re
import secrets
import string
from getpass import getpass
from dataclasses import dataclass
from typing import List, Optional, Sequence

import bcrypt
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# OWASP and modern industry guidance generally recommends:
# - PBKDF2 iterations >= 100,000 (higher is typically better for server auth)
# - bcrypt cost >= 12
# - scrypt with memory-hard parameters (defaults selected below)
MIN_PBKDF2_ITERATIONS = 100_000
MIN_SALT_LENGTH = 16
DEFAULT_SALT_LENGTH = MIN_SALT_LENGTH
DEFAULT_PBKDF2_ITERATIONS = 300_000
DEFAULT_PBKDF2_KEY_LENGTH = 32

MIN_BCRYPT_ROUNDS = 12
DEFAULT_BCRYPT_ROUNDS = 12

# scrypt default aims for strong security with practical runtime on modern systems.
DEFAULT_SCRYPT_N = 2**15  # CPU/memory cost parameter
DEFAULT_SCRYPT_R = 8      # block size
DEFAULT_SCRYPT_P = 1      # parallelization
DEFAULT_SCRYPT_KEY_LENGTH = 32

# Small baseline dictionary for fast common-password checks.
# In production systems, consider loading a larger curated blocklist.
COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password123",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "letmein",
        "admin",
        "welcome",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "princess",
        "trustno1",
        "passw0rd",
        "changeme",
    }
)


class PasswordKDFError(ValueError):
    """Raised when invalid parameters are provided to KDF/hash operations."""


@dataclass(frozen=True)
class PasswordStrengthResult:
    """
    Structured password strength analysis output.

    Attributes:
        score: Integer score between 0 and 100.
        rating: Human-readable rating label.
        entropy_bits: Estimated entropy in bits.
        recommendations: Actionable recommendations to improve password security.
    """

    score: int
    rating: str
    entropy_bits: float
    recommendations: List[str]


def generate_salt(length: int = MIN_SALT_LENGTH) -> bytes:
    """
    Generate a cryptographically secure random salt.

    Args:
        length: Desired salt length in bytes (must be >= 16).

    Returns:
        A securely generated random salt as bytes.

    Raises:
        PasswordKDFError: If length is below minimum security threshold.
    """
    if length < MIN_SALT_LENGTH:
        raise PasswordKDFError(
            f"Salt length must be at least {MIN_SALT_LENGTH} bytes."
        )
    return secrets.token_bytes(length)


def _validate_password(password: str) -> None:
    """Validate that password is a non-empty string."""
    if not isinstance(password, str):
        raise PasswordKDFError("Password must be a string.")
    if not password:
        raise PasswordKDFError("Password must not be empty.")


def _validate_salt(salt: bytes, min_length: int = MIN_SALT_LENGTH) -> None:
    """Validate that salt is bytes and meets minimum length."""
    if not isinstance(salt, bytes):
        raise PasswordKDFError("Salt must be bytes.")
    if len(salt) < min_length:
        raise PasswordKDFError(f"Salt must be at least {min_length} bytes.")


def derive_key_pbkdf2(
    password: str,
    salt: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    key_length: int = DEFAULT_PBKDF2_KEY_LENGTH,
) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: Input password as text.
        salt: Cryptographic salt (16+ bytes recommended and enforced).
        iterations: PBKDF2 iteration count (minimum 100,000).
        key_length: Output key length in bytes.

    Returns:
        Derived key bytes of length `key_length`.

    Raises:
        PasswordKDFError: On invalid parameters.

    Security considerations:
        - Use a unique random salt for every password.
        - Store salt and iteration count alongside derived key metadata.
        - Higher iterations increase brute-force cost but also CPU time.
    """
    _validate_password(password)
    _validate_salt(salt)

    if iterations < MIN_PBKDF2_ITERATIONS:
        raise PasswordKDFError(
            f"PBKDF2 iterations must be >= {MIN_PBKDF2_ITERATIONS}."
        )
    if key_length <= 0:
        raise PasswordKDFError("key_length must be greater than 0.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def verify_key_pbkdf2(
    password: str,
    salt: bytes,
    expected_key: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> bool:
    """
    Verify whether a password matches an expected PBKDF2-derived key.

    Args:
        password: Candidate password.
        salt: Original salt used for derivation.
        expected_key: Previously derived key to compare against.
        iterations: PBKDF2 iteration count originally used.

    Returns:
        True if password derives the expected key, otherwise False.

    Raises:
        PasswordKDFError: On invalid parameters.

    Security considerations:
        - Comparison is done with constant-time equality check.
    """
    _validate_password(password)
    _validate_salt(salt)
    if not isinstance(expected_key, bytes) or not expected_key:
        raise PasswordKDFError("expected_key must be non-empty bytes.")

    derived = derive_key_pbkdf2(
        password=password,
        salt=salt,
        iterations=iterations,
        key_length=len(expected_key),
    )
    return bool(constant_time.bytes_eq(derived, expected_key))


def hash_password_bcrypt(
    password: str, rounds: int = DEFAULT_BCRYPT_ROUNDS
) -> bytes:
    """
    Hash a password with bcrypt.

    Args:
        password: Password string to hash.
        rounds: bcrypt cost/work factor (minimum 12).

    Returns:
        bcrypt hash bytes including algorithm version, cost, and salt.

    Raises:
        PasswordKDFError: On invalid input or weak bcrypt rounds.

    Security considerations:
        - bcrypt includes per-hash random salt automatically.
        - Store hash as-is; all metadata needed for verification is embedded.
    """
    _validate_password(password)

    if rounds < MIN_BCRYPT_ROUNDS:
        raise PasswordKDFError(f"bcrypt rounds must be >= {MIN_BCRYPT_ROUNDS}.")

    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password_bytes, salt)


def verify_password_bcrypt(password: str, password_hash: bytes) -> bool:
    """
    Verify a password against a bcrypt hash.

    Args:
        password: Candidate password.
        password_hash: Stored bcrypt hash.

    Returns:
        True if password matches hash, otherwise False.

    Raises:
        PasswordKDFError: On invalid inputs.

    Security considerations:
        - bcrypt.checkpw performs constant-time verification internally.
    """
    _validate_password(password)
    if not isinstance(password_hash, bytes) or not password_hash:
        raise PasswordKDFError("password_hash must be non-empty bytes.")

    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), password_hash))
    except ValueError as exc:
        raise PasswordKDFError("Invalid bcrypt hash format.") from exc


def derive_key_scrypt(
    password: str,
    salt: bytes,
    n: int = DEFAULT_SCRYPT_N,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
    key_length: int = DEFAULT_SCRYPT_KEY_LENGTH,
) -> bytes:
    """
    Derive a key using the memory-hard scrypt KDF.

    Args:
        password: Input password.
        salt: Cryptographic salt (minimum 16 bytes).
        n: CPU/memory cost parameter (must be power of two and > 1).
        r: Block size parameter (positive integer).
        p: Parallelization parameter (positive integer).
        key_length: Output key length in bytes.

    Returns:
        Derived key bytes.

    Raises:
        PasswordKDFError: On invalid parameters.

    Security considerations:
        - scrypt is memory-hard, making large-scale brute force more expensive.
        - Use per-secret random salts and store parameters with metadata.
    """
    _validate_password(password)
    _validate_salt(salt)

    if n <= 1 or (n & (n - 1)) != 0:
        raise PasswordKDFError("scrypt n must be a power of two greater than 1.")
    if r <= 0 or p <= 0:
        raise PasswordKDFError("scrypt r and p must be positive integers.")
    if key_length <= 0:
        raise PasswordKDFError("key_length must be greater than 0.")

    kdf = Scrypt(salt=salt, length=key_length, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def verify_key_scrypt(
    password: str,
    salt: bytes,
    expected_key: bytes,
    n: int = DEFAULT_SCRYPT_N,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
) -> bool:
    """
    Verify whether a password matches an expected scrypt-derived key.

    Args:
        password: Candidate password.
        salt: Original salt used for derivation.
        expected_key: Previously derived key.
        n: scrypt n parameter used for derivation.
        r: scrypt r parameter used for derivation.
        p: scrypt p parameter used for derivation.

    Returns:
        True if derived key matches expected key, otherwise False.

    Raises:
        PasswordKDFError: On invalid parameters.
    """
    _validate_password(password)
    _validate_salt(salt)
    if not isinstance(expected_key, bytes) or not expected_key:
        raise PasswordKDFError("expected_key must be non-empty bytes.")

    derived = derive_key_scrypt(
        password=password,
        salt=salt,
        n=n,
        r=r,
        p=p,
        key_length=len(expected_key),
    )
    return bool(constant_time.bytes_eq(derived, expected_key))


def _character_pool_size(password: str) -> int:
    """Estimate effective character pool size from character categories used."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool += 1
    return max(pool, 1)


def estimate_entropy_bits(password: str) -> float:
    """
    Estimate password entropy in bits using a character-pool approximation.

    Args:
        password: Password to evaluate.

    Returns:
        Estimated entropy in bits.
    """
    _validate_password(password)
    pool = _character_pool_size(password)
    return len(password) * math.log2(pool)


def evaluate_password_strength(
    password: str,
    common_passwords: Optional[Sequence[str]] = None,
) -> PasswordStrengthResult:
    """
    Evaluate password strength and provide actionable recommendations.

    Args:
        password: Password to evaluate.
        common_passwords: Optional custom dictionary for common-password checks.
            If omitted, a built-in baseline list is used.

    Returns:
        PasswordStrengthResult with score (0-100), rating, entropy estimate,
        and recommendations.

    Scoring factors:
        - Length
        - Character diversity
        - Entropy estimate
        - Common password/blocklist checks
        - Repeated/sequential pattern penalties
    """
    _validate_password(password)
    dictionary = (
        {p.lower() for p in common_passwords} if common_passwords else COMMON_PASSWORDS
    )
    pw_lower = password.lower()

    recommendations: List[str] = []
    score = 0

    # Length scoring (max 35)
    length = len(password)
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 25
    elif length >= 10:
        score += 15
        recommendations.append("Use at least 12 characters; 16+ is stronger.")
    else:
        score += 5
        recommendations.append("Increase password length to at least 12 characters.")

    # Diversity scoring (max 25)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    classes_used = sum((has_lower, has_upper, has_digit, has_special))
    score += classes_used * 6
    if classes_used < 3:
        recommendations.append(
            "Use a mix of uppercase, lowercase, digits, and symbols."
        )
    if not has_special:
        recommendations.append("Add at least one special character.")

    # Entropy scoring (max 30)
    entropy_bits = estimate_entropy_bits(password)
    if entropy_bits >= 80:
        score += 30
    elif entropy_bits >= 60:
        score += 22
    elif entropy_bits >= 40:
        score += 12
        recommendations.append(
            "Increase unpredictability with longer, less-patterned content."
        )
    else:
        score += 5
        recommendations.append("Password entropy is low; make it more complex.")

    # Common password and predictable patterns (penalties)
    if pw_lower in dictionary:
        score -= 35
        recommendations.append("Avoid common passwords; use unique passphrases.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        recommendations.append("Avoid repeated characters or repeated short patterns.")

    sequences = ("1234", "abcd", "qwerty", "password", "admin")
    if any(seq in pw_lower for seq in sequences):
        score -= 12
        recommendations.append("Avoid keyboard or alphabetical/numeric sequences.")

    score = max(0, min(100, score))

    if score >= 85:
        rating = "Very Strong"
    elif score >= 70:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    elif score >= 30:
        rating = "Weak"
    else:
        rating = "Very Weak"

    # Deduplicate while preserving insertion order.
    recommendations = list(dict.fromkeys(recommendations))

    return PasswordStrengthResult(
        score=score,
        rating=rating,
        entropy_bits=round(entropy_bits, 2),
        recommendations=recommendations,
    )


def generate_password_report(password: str, salt_length: int = DEFAULT_SALT_LENGTH) -> dict:
    """
    Run all local checks/derivations for a given password and return a report.

    Args:
        password: Password to test locally.
        salt_length: Salt size in bytes for PBKDF2 and scrypt (default 16).

    Returns:
        Dictionary containing PBKDF2, bcrypt, scrypt, and strength details.
    """
    _validate_password(password)

    pbkdf2_salt = generate_salt(salt_length)
    pbkdf2_key = derive_key_pbkdf2(password=password, salt=pbkdf2_salt)
    pbkdf2_verify = verify_key_pbkdf2(password, pbkdf2_salt, pbkdf2_key)

    bcrypt_hash = hash_password_bcrypt(password, rounds=DEFAULT_BCRYPT_ROUNDS)
    bcrypt_verify = verify_password_bcrypt(password, bcrypt_hash)

    scrypt_salt = generate_salt(salt_length)
    scrypt_key = derive_key_scrypt(password=password, salt=scrypt_salt)
    scrypt_verify = verify_key_scrypt(password, scrypt_salt, scrypt_key)

    strength = evaluate_password_strength(password)

    return {
        "pbkdf2_key_length": len(pbkdf2_key),
        "pbkdf2_verify": pbkdf2_verify,
        "bcrypt_hash": bcrypt_hash.decode("utf-8"),
        "bcrypt_verify": bcrypt_verify,
        "scrypt_key_length": len(scrypt_key),
        "scrypt_verify": scrypt_verify,
        "strength_score": strength.score,
        "strength_rating": strength.rating,
        "entropy_bits": strength.entropy_bits,
        "recommendations": strength.recommendations or ["Looks good."],
    }


if __name__ == "__main__":
    try:
        print("Enter your password for local testing (input hidden):")
        user_password = getpass("Password: ")
        report = generate_password_report(user_password)

        print("PBKDF2 key length:", report["pbkdf2_key_length"])
        print("PBKDF2 verify:", report["pbkdf2_verify"])
        print("bcrypt hash:", report["bcrypt_hash"])
        print("bcrypt verify:", report["bcrypt_verify"])
        print("scrypt key length:", report["scrypt_key_length"])
        print("scrypt verify:", report["scrypt_verify"])
        print("Strength score:", report["strength_score"])
        print("Strength rating:", report["strength_rating"])
        print("Entropy bits:", report["entropy_bits"])
        print("Recommendations:", report["recommendations"])
    except PasswordKDFError as exc:
        print("Error:", str(exc))
