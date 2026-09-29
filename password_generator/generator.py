"""Cryptographically secure random password and passphrase generator."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .exceptions import (
    ConstraintViolationError,
    EmptyCharacterSetError,
    InvalidLengthError,
    ValidationError,
)

DEFAULT_SYMBOLS: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AMBIGUOUS_CHARS: str = "l1IOo0"

# Curated wordlist for secure, memorable passphrase generation
DEFAULT_WORDLIST: tuple[str, ...] = (
    "beacon", "breeze", "cactus", "castle", "canyon", "comet", "crater", "crystal",
    "desert", "dragon", "eagle", "ember", "falcon", "forest", "galaxy", "glacier",
    "granite", "harbor", "haven", "horizon", "island", "jungle", "lagoon", "lantern",
    "magnet", "marble", "meadow", "meteor", "mirage", "monarch", "moon", "nebula",
    "oasis", "ocean", "orbit", "panther", "pebble", "phoenix", "planet", "prism",
    "pulsar", "pyramid", "quartz", "quiver", "radiant", "raptor", "reef", "ridge",
    "river", "rocket", "safari", "shadow", "shield", "silver", "solstice", "spark",
    "sphere", "spiral", "summit", "tempest", "thunder", "timber", "titan", "topaz",
    "torrent", "tracer", "traveler", "tundra", "twilight", "valley", "vapor", "vector",
    "velocity", "vortex", "voyage", "walrus", "water", "whisper", "wildlife", "wind",
    "wizard", "zenith", "zephyr", "amber", "arctic", "arrow", "aurora", "badger",
    "bison", "blizzard", "cavalier", "cedar", "clover", "compass", "cypress", "dawn",
    "delta", "dune", "echo", "element", "everest", "feather", "flame", "fossil",
    "frost", "garnet", "geyser", "grove", "hawk", "lotus", "moss", "nova",
    "onyx", "opal", "prairie", "raven", "redwood", "ripple", "sage", "sapphire",
    "sierra", "storm", "stratus", "talon", "thistle", "tulip", "vanguard", "willow"
)


@dataclass
class PasswordPolicy:
    """Configuration options and constraints for password generation."""
    length: int = 16
    include_lower: bool = True
    include_upper: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    custom_symbols: Optional[str] = None
    exclude_ambiguous: bool = False
    exclude_chars: str = ""
    min_lower: int = 0
    min_upper: int = 0
    min_digits: int = 0
    min_symbols: int = 0
    enforce_all_categories: bool = True

    def validate(self) -> None:
        """Validate configuration settings and constraints."""
        # Type and basic range validations
        if not isinstance(self.length, int) or isinstance(self.length, bool):
            raise ValidationError(f"Length must be an integer, got {type(self.length).__name__}")
        if self.length <= 0:
            raise InvalidLengthError(f"Length must be a positive integer, got {self.length}")
        if self.length > 4096:
            raise InvalidLengthError(f"Length {self.length} exceeds maximum allowed (4096)")

        for name, val in [
            ("min_lower", self.min_lower),
            ("min_upper", self.min_upper),
            ("min_digits", self.min_digits),
            ("min_symbols", self.min_symbols),
        ]:
            if not isinstance(val, int) or isinstance(val, bool):
                raise ValidationError(f"{name} must be an integer, got {type(val).__name__}")
            if val < 0:
                raise ValidationError(f"{name} cannot be negative, got {val}")

        # Check if any character category is enabled
        if not (self.include_lower or self.include_upper or self.include_digits or self.include_symbols):
            raise EmptyCharacterSetError("At least one character set must be enabled")

        # Conflict checks between include flags and minimum counts
        if not self.include_lower and self.min_lower > 0:
            raise ConstraintViolationError("Cannot specify min_lower > 0 when include_lower is False")
        if not self.include_upper and self.min_upper > 0:
            raise ConstraintViolationError("Cannot specify min_upper > 0 when include_upper is False")
        if not self.include_digits and self.min_digits > 0:
            raise ConstraintViolationError("Cannot specify min_digits > 0 when include_digits is False")
        if not self.include_symbols and self.min_symbols > 0:
            raise ConstraintViolationError("Cannot specify min_symbols > 0 when include_symbols is False")

        # Effective minimums
        effective_min = self._calculate_effective_minimums()
        total_min = sum(effective_min.values())

        if self.length < total_min:
            raise InvalidLengthError(
                f"Password length ({self.length}) is smaller than the required minimum characters ({total_min})"
            )

    def _calculate_effective_minimums(self) -> dict[str, int]:
        """Compute effective minimum counts per category."""
        mins = {
            "lower": self.min_lower,
            "upper": self.min_upper,
            "digits": self.min_digits,
            "symbols": self.min_symbols,
        }

        # If enforce_all_categories is True, default each enabled category to at least 1
        if self.enforce_all_categories:
            if self.include_lower and mins["lower"] == 0:
                mins["lower"] = 1
            if self.include_upper and mins["upper"] == 0:
                mins["upper"] = 1
            if self.include_digits and mins["digits"] == 0:
                mins["digits"] = 1
            if self.include_symbols and mins["symbols"] == 0:
                mins["symbols"] = 1

        return mins


class PasswordGenerator:
    """Secure random password generator using OS-level CSPRNG."""

    def __init__(self, policy: Optional[PasswordPolicy] = None) -> None:
        self.policy = policy or PasswordPolicy()
        self._rng = secrets.SystemRandom()

    def _build_character_pools(self, policy: PasswordPolicy) -> tuple[dict[str, str], str]:
        """Build filtered character pools according to policy rules."""
        symbols = policy.custom_symbols if policy.custom_symbols is not None else DEFAULT_SYMBOLS
        exclude_set = set(policy.exclude_chars)

        if policy.exclude_ambiguous:
            exclude_set.update(AMBIGUOUS_CHARS)

        category_pools: dict[str, str] = {}

        if policy.include_lower:
            pool = "".join(c for c in string.ascii_lowercase if c not in exclude_set)
            if not pool:
                raise EmptyCharacterSetError("No lowercase characters available after exclusions")
            category_pools["lower"] = pool

        if policy.include_upper:
            pool = "".join(c for c in string.ascii_uppercase if c not in exclude_set)
            if not pool:
                raise EmptyCharacterSetError("No uppercase characters available after exclusions")
            category_pools["upper"] = pool

        if policy.include_digits:
            pool = "".join(c for c in string.digits if c not in exclude_set)
            if not pool:
                raise EmptyCharacterSetError("No digit characters available after exclusions")
            category_pools["digits"] = pool

        if policy.include_symbols:
            pool = "".join(c for c in symbols if c not in exclude_set)
            if not pool:
                raise EmptyCharacterSetError("No symbol characters available after exclusions")
            category_pools["symbols"] = pool

        combined_pool = "".join(category_pools.values())
        if not combined_pool:
            raise EmptyCharacterSetError("Combined character pool is empty")

        return category_pools, combined_pool

    def generate(self, policy: Optional[PasswordPolicy] = None) -> str:
        """Generate a single cryptographically secure random password."""
        active_policy = policy or self.policy
        active_policy.validate()

        category_pools, combined_pool = self._build_character_pools(active_policy)
        effective_mins = active_policy._calculate_effective_minimums()

        result_chars: List[str] = []

        # 1. Fill guaranteed minimum characters per category
        for cat, count in effective_mins.items():
            if count > 0 and cat in category_pools:
                pool = category_pools[cat]
                for _ in range(count):
                    result_chars.append(self._rng.choice(pool))

        # 2. Fill remaining length from combined pool
        remaining = active_policy.length - len(result_chars)
        for _ in range(remaining):
            result_chars.append(self._rng.choice(combined_pool))

        # 3. Cryptographically secure shuffle of result characters
        self._rng.shuffle(result_chars)
        return "".join(result_chars)

    def generate_multiple(self, count: int, policy: Optional[PasswordPolicy] = None) -> List[str]:
        """Generate multiple secure passwords."""
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValidationError(f"Count must be an integer, got {type(count).__name__}")
        if count <= 0:
            raise ValidationError(f"Count must be a positive integer, got {count}")
        if count > 10000:
            raise ValidationError(f"Count {count} exceeds maximum allowed batch size (10000)")

        return [self.generate(policy) for _ in range(count)]


def generate_password(
    length: int = 16,
    include_lower: bool = True,
    include_upper: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    custom_symbols: Optional[str] = None,
    exclude_ambiguous: bool = False,
    exclude_chars: str = "",
    min_lower: int = 0,
    min_upper: int = 0,
    min_digits: int = 0,
    min_symbols: int = 0,
    enforce_all_categories: bool = True,
) -> str:
    """Convenience function to generate a secure random password."""
    policy = PasswordPolicy(
        length=length,
        include_lower=include_lower,
        include_upper=include_upper,
        include_digits=include_digits,
        include_symbols=include_symbols,
        custom_symbols=custom_symbols,
        exclude_ambiguous=exclude_ambiguous,
        exclude_chars=exclude_chars,
        min_lower=min_lower,
        min_upper=min_upper,
        min_digits=min_digits,
        min_symbols=min_symbols,
        enforce_all_categories=enforce_all_categories,
    )
    return PasswordGenerator(policy).generate()


def generate_passphrase(
    words_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True,
    wordlist: Optional[Sequence[str]] = None,
) -> str:
    """Generate a secure, memorable passphrase using random words."""
    if not isinstance(words_count, int) or isinstance(words_count, bool):
        raise ValidationError(f"words_count must be an integer, got {type(words_count).__name__}")
    if words_count < 2:
        raise InvalidLengthError(f"Passphrase must have at least 2 words, got {words_count}")
    if words_count > 100:
        raise InvalidLengthError(f"Passphrase cannot exceed 100 words, got {words_count}")

    active_wordlist = list(DEFAULT_WORDLIST if wordlist is None else wordlist)
    if not active_wordlist:
        raise EmptyCharacterSetError("Wordlist cannot be empty")

    rng = secrets.SystemRandom()
    chosen_words = [rng.choice(active_wordlist) for _ in range(words_count)]

    if capitalize:
        chosen_words = [w.capitalize() for w in chosen_words]

    if include_number:
        # Append a cryptographically random number (0-99) to a random word
        rand_idx = rng.randrange(len(chosen_words))
        chosen_words[rand_idx] = f"{chosen_words[rand_idx]}{rng.randint(0, 99)}"

    return separator.join(chosen_words)
