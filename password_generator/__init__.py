"""A complete, cryptographically secure password generator package for Python."""

from .exceptions import (
    ConstraintViolationError,
    EmptyCharacterSetError,
    InvalidLengthError,
    PasswordGeneratorError,
    ValidationError,
)
from .generator import (
    DEFAULT_SYMBOLS,
    PasswordGenerator,
    PasswordPolicy,
    generate_passphrase,
    generate_password,
)
from .strength import (
    StrengthReport,
    calculate_entropy,
    calculate_pool_size,
    evaluate_strength,
)

__version__ = "1.0.0"

__all__ = [
    "PasswordGenerator",
    "PasswordPolicy",
    "generate_password",
    "generate_passphrase",
    "evaluate_strength",
    "calculate_entropy",
    "calculate_pool_size",
    "StrengthReport",
    "PasswordGeneratorError",
    "InvalidLengthError",
    "EmptyCharacterSetError",
    "ConstraintViolationError",
    "ValidationError",
    "DEFAULT_SYMBOLS",
]
