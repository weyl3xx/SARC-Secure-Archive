import re
import math
import secrets
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import List


MIN_LENGTH: int = 12
MAX_LENGTH: int = 128

_UPPERCASE   = string.ascii_uppercase
_LOWERCASE   = string.ascii_lowercase
_DIGITS      = string.digits
_SPECIAL     = "!@#$%^&*()-_=+[]{}|;:,.<>?"
_ALL_CHARS   = _UPPERCASE + _LOWERCASE + _DIGITS + _SPECIAL


class PasswordStrength(Enum):
    WEAK        = "weak"
    FAIR        = "fair"
    STRONG      = "strong"
    VERY_STRONG = "very strong"


@dataclass
class ValidationResult:
    is_valid: bool
    strength: PasswordStrength
    entropy_bits: float
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"  Strength:  {self.strength.value}",
            f"  Entropy:    {self.entropy_bits:.1f} bits",
        ]
        if self.errors:
            lines.append("  Errors:")
            lines.extend(f"    ✗ {e}" for e in self.errors)
        if self.warnings:
            lines.append("  Warnings:")
            lines.extend(f"    ⚠ {w}" for w in self.warnings)
        return "\n".join(lines)


def validate_password(password: str) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []

    if len(password) < MIN_LENGTH:
        errors.append(
            f"Too short: {len(password)} characters "
            f"(minimum {MIN_LENGTH})"
        )

    if len(password) > MAX_LENGTH:
        errors.append(
            f"Too long: {len(password)} characters "
            f"(maximum {MAX_LENGTH})"
        )

    if not re.search(r"[A-Z]", password):
        errors.append("No uppercase letters (A–Z)")

    if not re.search(r"[a-z]", password):
        errors.append("No lowercase letters (a–z)")

    if not re.search(r"\d", password):
        errors.append("No digits (0–9)")

    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password):
        errors.append("No special characters (!@#$%^&*…)")

    if re.search(r"(.)\1{2,}", password):
        warnings.append("Repeated characters detected (aaa, 111…)")

    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|asd)", password.lower()):
        warnings.append("Predictable sequence detected (123, qwe, abc…)")

    common_patterns = ["password", "qwerty", "admin", "login", "secret"]
    for pattern in common_patterns:
        if pattern in password.lower():
            warnings.append(f"Password contains common word: «{pattern}»")
            break

    entropy = _calculate_entropy(password)
    strength = _classify_strength(entropy, len(password))

    return ValidationResult(
        is_valid=len(errors) == 0,
        strength=strength,
        entropy_bits=entropy,
        errors=errors,
        warnings=warnings,
    )


def _calculate_entropy(password: str) -> float:
    alphabet_size = 0

    if re.search(r"[a-z]", password):
        alphabet_size += 26
    if re.search(r"[A-Z]", password):
        alphabet_size += 26
    if re.search(r"\d", password):
        alphabet_size += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password):
        alphabet_size += len(_SPECIAL)
    if re.search(r"[^\w!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password):
        alphabet_size += 32

    if alphabet_size == 0:
        return 0.0

    return len(password) * math.log2(alphabet_size)


def _classify_strength(entropy: float, length: int) -> PasswordStrength:
    if entropy < 40 or length < MIN_LENGTH:
        return PasswordStrength.WEAK
    elif entropy < 60:
        return PasswordStrength.FAIR
    elif entropy < 80:
        return PasswordStrength.STRONG
    else:
        return PasswordStrength.VERY_STRONG


def generate_password(length: int = 20) -> str:
    if length < MIN_LENGTH:
        raise ValueError(
            f"Password length must be at least {MIN_LENGTH} characters, "
            f"got: {length}"
        )
    if length > MAX_LENGTH:
        raise ValueError(
            f"Password length cannot exceed {MAX_LENGTH} characters, "
            f"got: {length}"
        )

    mandatory = [
        secrets.choice(_UPPERCASE),
        secrets.choice(_LOWERCASE),
        secrets.choice(_DIGITS),
        secrets.choice(_SPECIAL),
    ]

    rest = [secrets.choice(_ALL_CHARS) for _ in range(length - len(mandatory))]

    combined = mandatory + rest
    secrets.SystemRandom().shuffle(combined)

    return "".join(combined)


def generate_password_suggestions(count: int = 3, length: int = 20) -> List[str]:
    return [generate_password(length) for _ in range(count)]


def print_password_policy() -> None:
    print("  Password Requirements:")
    print(f"    • Length: from {MIN_LENGTH} to {MAX_LENGTH} characters")
    print("    • At least one uppercase letter (A-Z)")
    print("    • At least one lowercase letter (a-z)")
    print("    • At least one digit (0-9)")
    print("    • At least one special character (!@#$%^&*...)")


def print_suggestions(length: int = 20) -> None:
    print("\n  Suggested passwords (generated by cryptographically strong RNG):")
    for i, pwd in enumerate(generate_password_suggestions(3, length), 1):
        result = validate_password(pwd)
        print(f"    {i}. {pwd}  [{result.strength.value}, {result.entropy_bits:.0f} bits]")
    print()
