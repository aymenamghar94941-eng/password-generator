"""Password strength evaluation and entropy calculation."""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class StrengthReport:
    """Represents a detailed strength evaluation report for a password."""
    password: str
    length: int
    pool_size: int
    entropy_bits: float
    rating: str
    score: int  # 0 to 4
    feedback: List[str] = field(default_factory=list)

    @property
    def is_strong(self) -> bool:
        """Return True if password is rated Strong or Very Strong."""
        return self.score >= 3

    def to_dict(self) -> dict:
        """Serialize the report to a dictionary."""
        return {
            "length": self.length,
            "pool_size": self.pool_size,
            "entropy_bits": round(self.entropy_bits, 2),
            "rating": self.rating,
            "score": self.score,
            "is_strong": self.is_strong,
            "feedback": list(self.feedback),
        }


def calculate_pool_size(password: str) -> int:
    """Calculate the theoretical character pool size based on character classes in password."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    # Count any remaining characters (spaces, unicode, etc.)
    standard_chars = set(string.ascii_letters + string.digits + string.punctuation)
    extra_unique = len(set(c for c in password if c not in standard_chars))
    pool += extra_unique
    return pool


def calculate_entropy(password: str, pool_size: int | None = None) -> float:
    """Calculate the information entropy (in bits) of the password.

    Formula: Entropy = length * log2(pool_size)
    """
    if not password:
        return 0.0
    if pool_size is None or pool_size <= 0:
        pool_size = calculate_pool_size(password)
    if pool_size <= 1:
        return 0.0
    return len(password) * math.log2(pool_size)


def evaluate_strength(password: str) -> StrengthReport:
    """Evaluate password strength and return a comprehensive StrengthReport."""
    if not isinstance(password, str):
        raise TypeError(f"Expected password as string, got {type(password).__name__}")

    length = len(password)
    if length == 0:
        return StrengthReport(
            password="",
            length=0,
            pool_size=0,
            entropy_bits=0.0,
            rating="Empty",
            score=0,
            feedback=["Password is empty."],
        )

    pool_size = calculate_pool_size(password)
    entropy = calculate_entropy(password, pool_size)
    feedback: List[str] = []

    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    if not has_lower:
        feedback.append("Add lowercase letters.")
    if not has_upper:
        feedback.append("Add uppercase letters.")
    if not has_digit:
        feedback.append("Add numbers.")
    if not has_symbol:
        feedback.append("Add special characters / symbols.")
    if length < 8:
        feedback.append("Password is too short (minimum 8 characters recommended).")
    elif length < 12:
        feedback.append("Consider using at least 12 characters for improved security.")

    # Rating based on entropy (NIST and standard cryptographic guidance)
    # < 28 bits: Very Weak
    # 28 - 35 bits: Weak
    # 36 - 59 bits: Moderate
    # 60 - 127 bits: Strong
    # >= 128 bits: Very Strong
    if entropy < 28:
        rating = "Very Weak"
        score = 0
    elif entropy < 36:
        rating = "Weak"
        score = 1
    elif entropy < 60:
        rating = "Moderate"
        score = 2
    elif entropy < 128:
        rating = "Strong"
        score = 3
    else:
        rating = "Very Strong"
        score = 4

    if not feedback:
        feedback.append("Password meets all standard security recommendations.")

    return StrengthReport(
        password=password,
        length=length,
        pool_size=pool_size,
        entropy_bits=entropy,
        rating=rating,
        score=score,
        feedback=feedback,
    )
