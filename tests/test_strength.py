"""Unit tests for password strength evaluation and entropy calculations."""

import pytest

from password_generator.strength import (
    calculate_entropy,
    calculate_pool_size,
    evaluate_strength,
)


class TestPasswordStrength:
    """Test suite for strength evaluator and entropy metrics."""

    def test_pool_size_calculation(self):
        """Test character pool size calculations based on present character classes."""
        assert calculate_pool_size("abc") == 26
        assert calculate_pool_size("ABC") == 26
        assert calculate_pool_size("123") == 10
        assert calculate_pool_size("!@#") == 32
        assert calculate_pool_size("aA1!") == 26 + 26 + 10 + 32  # 94

    def test_entropy_calculation(self):
        """Test entropy bits calculation."""
        # 10 chars from 94 pool: 10 * log2(94) approx 65.54 bits
        entropy = calculate_entropy("aA1!bB2@cC", pool_size=94)
        assert 65.0 < entropy < 66.0

    def test_evaluate_empty_password(self):
        """Test evaluating an empty password."""
        report = evaluate_strength("")
        assert report.length == 0
        assert report.entropy_bits == 0.0
        assert report.rating == "Empty"
        assert report.score == 0
        assert not report.is_strong

    def test_evaluate_weak_password(self):
        """Test evaluating a short, low-diversity password."""
        report = evaluate_strength("12345")
        assert report.length == 5
        assert report.rating in ["Very Weak", "Weak"]
        assert report.score < 2
        assert not report.is_strong
        assert any("lowercase" in f for f in report.feedback)
        assert any("uppercase" in f for f in report.feedback)

    def test_evaluate_strong_password(self):
        """Test evaluating a high-entropy password."""
        report = evaluate_strength("K9#vL2$mQ8!zX7@p")
        assert report.length == 16
        assert report.rating in ["Strong", "Very Strong"]
        assert report.score >= 3
        assert report.is_strong

    def test_report_serialization(self):
        """Test converting StrengthReport to dict."""
        report = evaluate_strength("SecureP@ssw0rd!2026")
        data = report.to_dict()
        assert isinstance(data, dict)
        assert "entropy_bits" in data
        assert "rating" in data
        assert "score" in data
        assert "is_strong" in data
        assert isinstance(data["feedback"], list)

    def test_invalid_type_raises(self):
        """Test passing non-string raises TypeError."""
        with pytest.raises(TypeError, match="Expected password as string"):
            evaluate_strength(12345)  # type: ignore
