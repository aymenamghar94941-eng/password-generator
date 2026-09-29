"""Unit tests for the password and passphrase generator."""

import string
import pytest

from password_generator.exceptions import (
    ConstraintViolationError,
    EmptyCharacterSetError,
    InvalidLengthError,
    ValidationError,
)
from password_generator.generator import (
    AMBIGUOUS_CHARS,
    DEFAULT_SYMBOLS,
    PasswordGenerator,
    PasswordPolicy,
    generate_passphrase,
    generate_password,
)


class TestPasswordGenerator:
    """Test suite for PasswordGenerator and generate_password."""

    def test_default_password_generation(self):
        """Test default password generation has correct length and character mix."""
        password = generate_password()
        assert len(password) == 16
        assert isinstance(password, str)
        # Default settings should guarantee at least 1 of each category
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.ascii_uppercase for c in password)
        assert any(c in string.digits for c in password)
        assert any(c in DEFAULT_SYMBOLS for c in password)

    def test_custom_length(self):
        """Test generating passwords of various valid lengths."""
        for length in [4, 8, 12, 32, 64, 128]:
            pw = generate_password(length=length)
            assert len(pw) == length

    def test_digits_only(self):
        """Test generating digits-only passwords (e.g. PINs)."""
        pw = generate_password(
            length=8,
            include_lower=False,
            include_upper=False,
            include_digits=True,
            include_symbols=False,
        )
        assert len(pw) == 8
        assert all(c in string.digits for c in pw)

    def test_letters_only(self):
        """Test generating letters-only passwords."""
        pw = generate_password(
            length=12,
            include_lower=True,
            include_upper=True,
            include_digits=False,
            include_symbols=False,
        )
        assert len(pw) == 12
        assert all(c in string.ascii_letters for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)

    def test_no_symbols(self):
        """Test generating alphanumeric passwords without symbols."""
        pw = generate_password(length=20, include_symbols=False)
        assert len(pw) == 20
        assert all(c.isalnum() for c in pw)

    def test_custom_symbols(self):
        """Test specifying a custom subset of symbols."""
        custom = "!#"
        pw = generate_password(
            length=25,
            include_lower=False,
            include_upper=False,
            include_digits=False,
            include_symbols=True,
            custom_symbols=custom,
        )
        assert len(pw) == 25
        assert all(c in custom for c in pw)

    def test_exclude_characters(self):
        """Test excluding specific characters."""
        excluded = "abcxyz123"
        for _ in range(5):
            pw = generate_password(length=30, exclude_chars=excluded)
            assert not any(c in excluded for c in pw)

    def test_exclude_ambiguous_characters(self):
        """Test excluding visually ambiguous characters."""
        for _ in range(10):
            pw = generate_password(length=40, exclude_ambiguous=True)
            assert not any(c in AMBIGUOUS_CHARS for c in pw)

    def test_minimum_counts_guarantee(self):
        """Test enforcing minimum counts for each category."""
        policy = PasswordPolicy(
            length=20,
            min_lower=5,
            min_upper=4,
            min_digits=3,
            min_symbols=2,
        )
        gen = PasswordGenerator(policy)
        for _ in range(5):
            pw = gen.generate()
            assert len(pw) == 20
            lower_count = sum(1 for c in pw if c in string.ascii_lowercase)
            upper_count = sum(1 for c in pw if c in string.ascii_uppercase)
            digit_count = sum(1 for c in pw if c in string.digits)
            symbol_count = sum(1 for c in pw if c in DEFAULT_SYMBOLS)
            assert lower_count >= 5
            assert upper_count >= 4
            assert digit_count >= 3
            assert symbol_count >= 2

    def test_generate_multiple(self):
        """Test generating multiple unique passwords in batch."""
        gen = PasswordGenerator()
        passwords = gen.generate_multiple(10)
        assert len(passwords) == 10
        # Check uniqueness among the 10 passwords (16 char CSPRNG passwords will be unique)
        assert len(set(passwords)) == 10

    def test_randomness_non_deterministic(self):
        """Test that successive passwords are not identical."""
        p1 = generate_password(32)
        p2 = generate_password(32)
        assert p1 != p2


class TestInputValidationAndErrors:
    """Test validation rules and exception handling."""

    def test_invalid_length_zero_or_negative(self):
        """Test that non-positive lengths raise InvalidLengthError."""
        with pytest.raises(InvalidLengthError, match="positive integer"):
            generate_password(length=0)
        with pytest.raises(InvalidLengthError, match="positive integer"):
            generate_password(length=-5)

    def test_invalid_length_type(self):
        """Test that non-integer length raises ValidationError."""
        with pytest.raises(ValidationError, match="Length must be an integer"):
            generate_password(length="16")  # type: ignore
        with pytest.raises(ValidationError, match="Length must be an integer"):
            generate_password(length=12.5)  # type: ignore
        with pytest.raises(ValidationError, match="Length must be an integer"):
            generate_password(length=True)  # type: ignore

    def test_length_exceeds_maximum(self):
        """Test that excessive length raises InvalidLengthError."""
        with pytest.raises(InvalidLengthError, match="exceeds maximum"):
            generate_password(length=5000)

    def test_negative_minimum_counts(self):
        """Test that negative minimum character counts raise ValidationError."""
        with pytest.raises(ValidationError, match="cannot be negative"):
            generate_password(min_digits=-1)
        with pytest.raises(ValidationError, match="must be an integer"):
            generate_password(min_upper=2.5)  # type: ignore

    def test_all_categories_disabled(self):
        """Test that disabling all categories raises EmptyCharacterSetError."""
        with pytest.raises(EmptyCharacterSetError, match="At least one character set"):
            generate_password(
                include_lower=False,
                include_upper=False,
                include_digits=False,
                include_symbols=False,
            )

    def test_constraint_violation_disabled_category_with_min(self):
        """Test requiring minimum for a disabled category raises ConstraintViolationError."""
        with pytest.raises(ConstraintViolationError, match="Cannot specify min_digits > 0"):
            generate_password(include_digits=False, min_digits=2)

        with pytest.raises(ConstraintViolationError, match="Cannot specify min_upper > 0"):
            generate_password(include_upper=False, min_upper=1)

    def test_length_less_than_required_minimums(self):
        """Test that length smaller than sum of minimums raises InvalidLengthError."""
        with pytest.raises(InvalidLengthError, match="smaller than the required minimum"):
            generate_password(length=5, min_lower=3, min_upper=3)

    def test_all_characters_excluded_in_category(self):
        """Test that excluding all characters in a category raises EmptyCharacterSetError."""
        with pytest.raises(EmptyCharacterSetError, match="No digit characters available"):
            generate_password(
                length=10,
                include_lower=False,
                include_upper=False,
                include_digits=True,
                include_symbols=False,
                exclude_chars="0123456789",
            )

    def test_generate_multiple_validation(self):
        """Test validation for batch password generation."""
        gen = PasswordGenerator()
        with pytest.raises(ValidationError, match="Count must be a positive integer"):
            gen.generate_multiple(0)
        with pytest.raises(ValidationError, match="Count must be a positive integer"):
            gen.generate_multiple(-3)
        with pytest.raises(ValidationError, match="Count must be an integer"):
            gen.generate_multiple("five")  # type: ignore
        with pytest.raises(ValidationError, match="exceeds maximum"):
            gen.generate_multiple(20000)


class TestPassphraseGenerator:
    """Test suite for generate_passphrase."""

    def test_default_passphrase(self):
        """Test generating a default passphrase."""
        phrase = generate_passphrase()
        words = phrase.split("-")
        assert len(words) == 4
        # At least one word should have a number appended by default
        assert any(any(c.isdigit() for c in w) for w in words)
        # Words should be capitalized by default
        assert all(w[0].isupper() for w in words)

    def test_custom_passphrase_options(self):
        """Test passphrase with custom word count, separator, and no numbers."""
        phrase = generate_passphrase(
            words_count=5,
            separator=".",
            capitalize=False,
            include_number=False,
        )
        words = phrase.split(".")
        assert len(words) == 5
        assert not any(c.isdigit() for c in phrase)
        assert phrase.islower()

    def test_passphrase_custom_wordlist(self):
        """Test passphrase generation using a custom wordlist."""
        custom_words = ["apple", "banana", "cherry"]
        phrase = generate_passphrase(
            words_count=3,
            separator="_",
            capitalize=False,
            include_number=False,
            wordlist=custom_words,
        )
        words = phrase.split("_")
        assert len(words) == 3
        assert all(w in custom_words for w in words)

    def test_passphrase_invalid_word_count(self):
        """Test passphrase validation on invalid word count."""
        with pytest.raises(InvalidLengthError, match="at least 2 words"):
            generate_passphrase(words_count=1)
        with pytest.raises(ValidationError, match="words_count must be an integer"):
            generate_passphrase(words_count=3.5)  # type: ignore

    def test_passphrase_empty_wordlist(self):
        """Test error when empty wordlist is provided."""
        with pytest.raises(EmptyCharacterSetError, match="Wordlist cannot be empty"):
            generate_passphrase(wordlist=[])

    def test_short_length_without_enforce_all(self):
        """Test short password (e.g. 2 chars) works when enforce_all_categories=False."""
        pw = generate_password(length=2, enforce_all_categories=False)
        assert len(pw) == 2

