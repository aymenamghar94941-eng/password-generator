# 🔐 Secure Password Generator

A robust, production-ready, cryptographically secure password and passphrase generator written in Python. Built adhering to modern security standards, utilizing the operating system's Cryptographically Secure Pseudo-Random Number Generator (CSPRNG via Python's standard `secrets` library).

---

## ✨ Features

- **Cryptographically Secure**: Built on Python's `secrets` module (using OS entropy source: `/dev/urandom`, Windows `BCryptGenRandom`).
- **Flexible Character Configuration**:
  - Uppercase letters (`A-Z`)
  - Lowercase letters (`a-z`)
  - Numeric digits (`0-9`)
  - Punctuation & special symbols (`!@#$%^&*...`)
  - Custom symbols selection
- **Guaranteed Category Inclusion**: Guarantees that at least one character from each enabled character class is present in the output.
- **Minimum Requirements**: Configure minimum counts for any category (e.g., at least 2 numbers and 2 symbols).
- **Ambiguous Characters Filter**: Option to filter visually ambiguous characters (`l, 1, I, o, 0, O`) to eliminate human error when typing credentials.
- **Passphrase Generator**: Generate memorable Diceware-style passphrases with custom separators, capitalization, and random numeric tokens.
- **Entropy & Strength Analyzer**: Calculates theoretical pool entropy in bits and rates password strength from *Very Weak* to *Very Strong* with actionable feedback.
- **Rich CLI & JSON Output**: Supports command line flags, clipboard copying, interactive wizard mode, and JSON output for scripting and CI/CD pipelines.
- **Fully Tested**: Extensive unit test suite powered by `pytest`.

---

## 📁 Project Structure

```text
password-generator/
├── password_generator/
│   ├── __init__.py          # Package exports and public API
│   ├── __main__.py          # Entrypoint for python -m password_generator
│   ├── cli.py               # Command-line interface and interactive wizard
│   ├── exceptions.py        # Custom domain exceptions
│   ├── generator.py         # Secure CSPRNG password & passphrase generation engine
│   └── strength.py          # Entropy metrics and strength evaluation
├── tests/
│   ├── __init__.py
│   ├── test_cli.py          # CLI integration and output tests
│   ├── test_generator.py    # Generator logic, validations, and edge cases
│   └── test_strength.py     # Strength evaluation and entropy tests
├── pyproject.toml           # Project metadata and test configuration
└── README.md                # Comprehensive documentation
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.8+ (tested on Python 3.14)

### Clone or Navigate to Directory

```bash
cd password-generator
```

### Optional: Install in Editable Mode

```bash
python -m pip install -e .
```

To run tests, ensure `pytest` is installed:

```bash
python -m pip install pytest
```

---

## 💻 CLI Usage

You can run the generator directly via Python module execution or the `password-gen` command (if installed):

```bash
python -m password_generator [OPTIONS]
```

### Quick Examples

#### 1. Default (16 characters, all character classes included)
```bash
python -m password_generator
# Output:
# r#9Vk2$mQ8!zX7@p
```

#### 2. Specify Length and Multiple Passwords
```bash
python -m password_generator -l 24 -n 3
```

#### 3. Analyze Password Strength & Entropy
```bash
python -m password_generator -l 20 --strength
# Output:
# X7#vL2$mQ8!zW1@pA9^d  [Entropy: 131.1 bits | Rating: Very Strong]
```

#### 4. Exclude Ambiguous Characters (`l, 1, I, o, 0, O`)
```bash
python -m password_generator --no-ambiguous
```

#### 5. Enforce Specific Minimums (e.g. at least 3 digits and 2 symbols)
```bash
python -m password_generator -l 16 --min-digits 3 --min-symbols 2
```

#### 6. Generate Memorable Passphrase
```bash
python -m password_generator --passphrase --words 4 --separator "-"
# Output:
# Galaxy-Falcon-Summit42-Glacier
```

#### 7. JSON Output (Ideal for automation/scripts)
```bash
python -m password_generator -l 20 --strength --json
# Output:
# {
#   "password": "...",
#   "length": 20,
#   "pool_size": 94,
#   "entropy_bits": 131.09,
#   "rating": "Very Strong",
#   "score": 4,
#   "is_strong": true,
#   "feedback": [
#     "Password meets all standard security recommendations."
#   ]
# }
```

#### 8. Interactive Wizard Mode
```bash
python -m password_generator --interactive
```

---

## 📖 CLI Options Reference

| Option | Short | Default | Description |
|---|---|---|---|
| `--length` | `-l` | `16` | Length of generated password |
| `--count` | `-n` | `1` | Number of passwords to generate |
| `--no-lower` | | `False` | Exclude lowercase letters (`a-z`) |
| `--no-upper` | | `False` | Exclude uppercase letters (`A-Z`) |
| `--no-digits` | | `False` | Exclude numeric digits (`0-9`) |
| `--no-symbols` | | `False` | Exclude symbols and punctuation |
| `--custom-symbols`| | `None` | Custom set of symbols (e.g. `!@#$`) |
| `--exclude` | | `""` | Specific characters to exclude |
| `--no-ambiguous`| | `False` | Exclude ambiguous characters (`l, 1, I, o, 0, O`) |
| `--min-lower` | | `0` | Minimum number of lowercase letters |
| `--min-upper` | | `0` | Minimum number of uppercase letters |
| `--min-digits` | | `0` | Minimum number of numeric digits |
| `--min-symbols` | | `0` | Minimum number of special symbols |
| `--strength` | `-s` | `False` | Display entropy and security evaluation |
| `--passphrase` | `-p` | `False` | Generate a memorable passphrase |
| `--words` | | `4` | Number of words in passphrase mode |
| `--separator` | | `"-"` | Separator character in passphrase mode |
| `--no-capitalize`| | `False` | Keep passphrase words lowercase |
| `--no-number` | | `False` | Omit random number in passphrase |
| `--copy` | `-c` | `False` | Copy generated password to system clipboard |
| `--json` | | `False` | Output in structured JSON format |
| `--interactive` | `-i` | `False` | Run interactive configuration wizard |

---

## 🐍 Python API Usage

You can easily integrate the generator into any Python application or script:

### Basic Generation

```python
from password_generator import generate_password

# 16-character secure password with default character sets
password = generate_password()
print(password)

# Custom length without symbols
alphanumeric = generate_password(length=12, include_symbols=False)
print(alphanumeric)
```

### Advanced Policy Configuration

```python
from password_generator import PasswordGenerator, PasswordPolicy

policy = PasswordPolicy(
    length=20,
    include_lower=True,
    include_upper=True,
    include_digits=True,
    include_symbols=True,
    exclude_ambiguous=True,      # Disallows l, 1, I, o, 0, O
    min_digits=3,                # Guarantees at least 3 digits
    min_symbols=3,               # Guarantees at least 3 symbols
)

generator = PasswordGenerator(policy)

# Generate a single password
secure_pwd = generator.generate()

# Generate a batch of 5 passwords
batch = generator.generate_multiple(5)
```

### Passphrase Generation

```python
from password_generator import generate_passphrase

phrase = generate_passphrase(words_count=4, separator="-", include_number=True)
print(phrase)
# Example: Horizon-Summit-Falcon88-Canyon
```

### Strength & Entropy Analysis

```python
from password_generator import evaluate_strength

report = evaluate_strength("Tr0ub4dor&3")

print(f"Entropy: {report.entropy_bits:.1f} bits")
print(f"Rating: {report.rating}")
print(f"Is Strong: {report.is_strong}")
print(f"Feedback: {report.feedback}")
```

### Error Handling

The package provides descriptive custom exceptions:

```python
from password_generator import (
    generate_password,
    InvalidLengthError,
    EmptyCharacterSetError,
    ConstraintViolationError,
    ValidationError,
)

try:
    # Attempting an invalid configuration (e.g. length less than minimum constraints)
    pw = generate_password(length=4, min_digits=3, min_symbols=2)
except InvalidLengthError as e:
    print(f"Length error: {e}")
except EmptyCharacterSetError as e:
    print(f"Empty character set error: {e}")
except ConstraintViolationError as e:
    print(f"Constraint error: {e}")
except ValidationError as e:
    print(f"Validation error: {e}")
```

---

## 🛡️ Security Details

- **Cryptographic Randomness**: The generator strictly avoids standard pseudo-random number generators (like Python's `random` module, which uses the predictable Mersenne Twister). Instead, it uses `secrets.SystemRandom` backed by OS-level CSPRNG.
- **Unbiased Shuffling**: When minimum character requirements are enforced, the assembled character list is shuffled using `SystemRandom().shuffle` (Fisher-Yates) to ensure character positions cannot be predicted.
- **Entropy Calculation**:
  Theoretical entropy in bits is calculated as:
  $$E = L \times \log_2(N)$$
  where $L$ is the password length and $N$ is the character pool size.

| Entropy Range | Rating | Typical Cracking Difficulty |
|---|---|---|
| $< 28$ bits | Very Weak | Vulnerable to instant brute-force |
| $28 - 35$ bits | Weak | Trivial for offline dictionary attacks |
| $36 - 59$ bits | Moderate | Moderate resistance |
| $60 - 127$ bits | Strong | Resistant to offline brute-force |
| $\ge 128$ bits | Very Strong | Nation-state & quantum brute-force resistance |

---

## 🧪 Running Tests

Execute the complete test suite using `pytest`:

```bash
python -m pytest
```

To run with verbose output and summary:

```bash
python -m pytest -v
```

---

## 📄 License

This project is licensed under the MIT License.
