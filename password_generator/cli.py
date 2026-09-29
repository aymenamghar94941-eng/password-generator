"""Command-line interface for the secure password generator."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import List, Optional

from .exceptions import PasswordGeneratorError
from .generator import (
    PasswordGenerator,
    PasswordPolicy,
    generate_passphrase,
    generate_password,
)
from .strength import evaluate_strength


def copy_to_clipboard(text: str) -> bool:
    """Attempt to copy text to clipboard using pyperclip or OS utilities."""
    try:
        import pyperclip  # type: ignore
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            process = subprocess.Popen(
                ["clip"],
                stdin=subprocess.PIPE,
                close_fds=True,
                shell=False
            )
            process.communicate(input=text.encode("utf-8"))
            return process.returncode == 0
        except Exception:
            return False
    elif sys.platform == "darwin":
        try:
            process = subprocess.Popen(
                ["pbcopy"],
                stdin=subprocess.PIPE,
                close_fds=True
            )
            process.communicate(input=text.encode("utf-8"))
            return process.returncode == 0
        except Exception:
            return False

    return False


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="password-gen",
        description="Cryptographically secure password and passphrase generator with strength analysis.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-l", "--length",
        type=int,
        default=16,
        help="Length of the generated password(s)"
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="Number of passwords to generate"
    )
    parser.add_argument(
        "--no-lower",
        action="store_true",
        help="Exclude lowercase letters (a-z)"
    )
    parser.add_argument(
        "--no-upper",
        action="store_true",
        help="Exclude uppercase letters (A-Z)"
    )
    parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude numbers (0-9)"
    )
    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude special characters / symbols"
    )
    parser.add_argument(
        "--custom-symbols",
        type=str,
        default=None,
        help="Custom set of special symbols to use"
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Specific characters to exclude from password"
    )
    parser.add_argument(
        "--no-ambiguous",
        action="store_true",
        help="Exclude visually ambiguous characters (l, 1, I, o, 0, O)"
    )
    parser.add_argument(
        "--min-lower",
        type=int,
        default=0,
        help="Minimum number of lowercase letters required"
    )
    parser.add_argument(
        "--min-upper",
        type=int,
        default=0,
        help="Minimum number of uppercase letters required"
    )
    parser.add_argument(
        "--min-digits",
        type=int,
        default=0,
        help="Minimum number of digits required"
    )
    parser.add_argument(
        "--min-symbols",
        type=int,
        default=0,
        help="Minimum number of symbols required"
    )
    parser.add_argument(
        "-s", "--strength",
        action="store_true",
        help="Display entropy and security strength evaluation"
    )
    parser.add_argument(
        "-p", "--passphrase",
        action="store_true",
        help="Generate a memorable passphrase instead of a random string"
    )
    parser.add_argument(
        "--words",
        type=int,
        default=4,
        help="Number of words in passphrase (passphrase mode only)"
    )
    parser.add_argument(
        "--separator",
        type=str,
        default="-",
        help="Separator character between words (passphrase mode only)"
    )
    parser.add_argument(
        "--no-capitalize",
        action="store_true",
        help="Do not capitalize passphrase words"
    )
    parser.add_argument(
        "--no-number",
        action="store_true",
        help="Do not include a random number in passphrase"
    )
    parser.add_argument(
        "-c", "--copy",
        action="store_true",
        help="Copy the generated password (or first password) to clipboard"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Launch interactive configuration wizard"
    )

    return parser


def run_interactive() -> int:
    """Run an interactive console prompt to configure and generate passwords."""
    print("=== Secure Password Generator Wizard ===")
    try:
        mode = input("Generate (1) Password or (2) Passphrase? [1]: ").strip()
        if mode == "2":
            words_str = input("Number of words [4]: ").strip() or "4"
            words = int(words_str)
            sep = input("Separator [-]: ") or "-"
            passphrase = generate_passphrase(words_count=words, separator=sep)
            report = evaluate_strength(passphrase)
            print(f"\nGenerated Passphrase: {passphrase}")
            print(f"Entropy: {report.entropy_bits:.1f} bits | Rating: {report.rating}")
            return 0

        length_str = input("Password length [16]: ").strip() or "16"
        length = int(length_str)

        use_lower = input("Include lowercase (a-z)? [Y/n]: ").strip().lower() != "n"
        use_upper = input("Include uppercase (A-Z)? [Y/n]: ").strip().lower() != "n"
        use_digits = input("Include digits (0-9)? [Y/n]: ").strip().lower() != "n"
        use_symbols = input("Include symbols (!@#...)? [Y/n]: ").strip().lower() != "n"
        no_ambiguous = input("Exclude ambiguous characters (l1IOo0)? [y/N]: ").strip().lower() == "y"
        count_str = input("Number of passwords to generate [1]: ").strip() or "1"
        count = int(count_str)

        policy = PasswordPolicy(
            length=length,
            include_lower=use_lower,
            include_upper=use_upper,
            include_digits=use_digits,
            include_symbols=use_symbols,
            exclude_ambiguous=no_ambiguous,
        )

        gen = PasswordGenerator(policy)
        passwords = gen.generate_multiple(count)

        print("\nGenerated Passwords:")
        for idx, pw in enumerate(passwords, 1):
            report = evaluate_strength(pw)
            print(f"[{idx}] {pw} (Rating: {report.rating}, Entropy: {report.entropy_bits:.1f} bits)")

        return 0
    except (ValueError, PasswordGeneratorError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.interactive:
        return run_interactive()

    try:
        results = []
        if args.passphrase:
            for _ in range(args.count):
                pw = generate_passphrase(
                    words_count=args.words,
                    separator=args.separator,
                    capitalize=not args.no_capitalize,
                    include_number=not args.no_number,
                )
                report = evaluate_strength(pw)
                results.append((pw, report))
        else:
            policy = PasswordPolicy(
                length=args.length,
                include_lower=not args.no_lower,
                include_upper=not args.no_upper,
                include_digits=not args.no_digits,
                include_symbols=not args.no_symbols,
                custom_symbols=args.custom_symbols,
                exclude_chars=args.exclude,
                exclude_ambiguous=args.no_ambiguous,
                min_lower=args.min_lower,
                min_upper=args.min_upper,
                min_digits=args.min_digits,
                min_symbols=args.min_symbols,
            )
            gen = PasswordGenerator(policy)
            passwords = gen.generate_multiple(args.count)
            for pw in passwords:
                report = evaluate_strength(pw)
                results.append((pw, report))

        # Output results
        if args.json:
            data = []
            for pw, rep in results:
                item = {"password": pw}
                if args.strength:
                    item.update(rep.to_dict())
                data.append(item)
            output = data if len(data) > 1 else data[0]
            print(json.dumps(output, indent=2))
        else:
            for pw, rep in results:
                if args.strength:
                    print(f"{pw}  [Entropy: {rep.entropy_bits:.1f} bits | Rating: {rep.rating}]")
                else:
                    print(pw)

        # Copy to clipboard if requested
        if args.copy and results:
            first_pw = results[0][0]
            if copy_to_clipboard(first_pw):
                if not args.json:
                    print("[Password copied to clipboard]", file=sys.stderr)
            else:
                if not args.json:
                    print("[Could not access clipboard]", file=sys.stderr)

        return 0

    except PasswordGeneratorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
