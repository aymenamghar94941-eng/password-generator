"""Custom exceptions for the password generator package."""


class PasswordGeneratorError(Exception):
    """Base exception for all password generator errors."""
    pass


class InvalidLengthError(PasswordGeneratorError, ValueError):
    """Raised when the specified password length is invalid or insufficient."""
    pass


class EmptyCharacterSetError(PasswordGeneratorError, ValueError):
    """Raised when no characters are available to generate a password."""
    pass


class ConstraintViolationError(PasswordGeneratorError, ValueError):
    """Raised when configuration constraints conflict with each other."""
    pass


class ValidationError(PasswordGeneratorError, ValueError):
    """Raised when general parameter validation fails."""
    pass
