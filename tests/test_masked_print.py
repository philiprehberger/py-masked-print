"""Tests for philiprehberger_masked_print."""

from __future__ import annotations

import logging
import re

from philiprehberger_masked_print import (
    MaskedFormatter,
    mask,
    mask_dict,
    register_pattern,
    register_sensitive_key,
)


class TestMask:
    def test_mask_long_string(self):
        # 13 chars: 4 visible + 6 masked + 3 visible = "abcd******xyz"
        assert mask("abcdefghijxyz") == "abcd******xyz"

    def test_mask_short_string_replaced_completely(self):
        assert mask("short") == "*****"

    def test_mask_empty_string(self):
        assert mask("") == ""

    def test_mask_custom_visibility(self):
        assert mask("0123456789abcdef", show_first=2, show_last=2) == "01" + "*" * 12 + "ef"

    def test_mask_custom_char(self):
        assert mask("abcdefghijxyz", mask_char="#") == "abcd######xyz"


class TestMaskDict:
    def test_masks_default_sensitive_keys(self):
        out = mask_dict({"username": "alice", "password": "supersecret123"})
        assert out["username"] == "alice"
        assert out["password"] != "supersecret123"
        assert "*" in str(out["password"])

    def test_recurses_into_nested_dicts(self):
        out = mask_dict({"db": {"host": "localhost", "password": "shh-very-secret"}})
        assert out["db"]["host"] == "localhost"  # type: ignore[index]
        assert "*" in str(out["db"]["password"])  # type: ignore[index]

    def test_case_insensitive_substring_match(self):
        out = mask_dict({"API_KEY": "abcdefghijxyz"})
        assert "*" in str(out["API_KEY"])

    def test_custom_sensitive_keys_override_defaults(self):
        out = mask_dict({"password": "still-shown"}, sensitive_keys={"foo"})
        assert out["password"] == "still-shown"

    def test_non_string_values_unchanged(self):
        out = mask_dict({"password": 12345, "active": True})
        assert out["password"] == 12345
        assert out["active"] is True


class TestMaskedFormatter:
    def _setup_logger(self) -> tuple[logging.Logger, logging.Handler, list[str]]:
        records: list[str] = []

        class _ListHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = _ListHandler()
        handler.setFormatter(MaskedFormatter("%(message)s"))
        logger = logging.getLogger(f"test-{id(handler)}")
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger, handler, records

    def test_redacts_openai_keys(self):
        logger, _, records = self._setup_logger()
        logger.info("using sk-abcdefghijklmnopqrstuvwxyz0123 for auth")
        assert "sk-abcdefghijklmnopqrstuvwxyz0123" not in records[0]

    def test_redacts_jwt(self):
        logger, _, records = self._setup_logger()
        logger.info("token=eyJhbGciOiJIUzI1NiJ9foobar123")
        assert "eyJhbGciOiJIUzI1NiJ9foobar123" not in records[0]

    def test_redacts_aws_access_key(self):
        logger, _, records = self._setup_logger()
        logger.info("AKIAIOSFODNN7EXAMPLE used")
        assert "AKIAIOSFODNN7EXAMPLE" not in records[0]

    def test_redacts_url_credentials(self):
        logger, _, records = self._setup_logger()
        logger.info("connect: https://user:topsecret@example.com/db")
        assert "user:topsecret@" not in records[0]
        assert "://***:***@" in records[0]


class TestRegisterPattern:
    def test_compiled_pattern_is_used(self):
        register_pattern(re.compile(r"PINPIN-\d{4}"))
        try:
            handler = logging.Handler()
            formatted = MaskedFormatter._mask_secrets("contains PINPIN-1234 secret")
        finally:
            # remove the just-added pattern to avoid bleeding into other tests
            from philiprehberger_masked_print import _SECRET_PATTERNS as patterns
            patterns.pop()
        assert "PINPIN-1234" not in formatted

    def test_string_pattern_compiled(self):
        register_pattern(r"CARD-\d{4}")
        try:
            from philiprehberger_masked_print import _SECRET_PATTERNS as patterns
            assert patterns[-1].pattern == r"CARD-\d{4}"
            formatted = MaskedFormatter._mask_secrets("CARD-9876 here")
            assert "CARD-9876" not in formatted
        finally:
            from philiprehberger_masked_print import _SECRET_PATTERNS as patterns
            patterns.pop()


class TestRegisterSensitiveKey:
    def test_added_key_is_masked(self):
        register_sensitive_key("nonce_value")
        try:
            out = mask_dict({"nonce_value": "abcdefghijxyz"})
            assert "*" in str(out["nonce_value"])
        finally:
            from philiprehberger_masked_print import _DEFAULT_SENSITIVE_KEYS as keys
            keys.discard("nonce_value")

    def test_case_insensitive_registration(self):
        register_sensitive_key("CustomTOKEN")
        try:
            out = mask_dict({"customToken": "abcdefghijxyz"})
            assert "*" in str(out["customToken"])
        finally:
            from philiprehberger_masked_print import _DEFAULT_SENSITIVE_KEYS as keys
            keys.discard("customtoken")
