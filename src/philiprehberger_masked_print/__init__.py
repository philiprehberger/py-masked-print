"""Automatically mask sensitive values (API keys, passwords, tokens) in logs and print output."""

from __future__ import annotations

import logging
import re

__all__ = [
    "MaskedFormatter",
    "mask",
    "mask_dict",
    "register_pattern",
    "register_sensitive_key",
]

_DEFAULT_SENSITIVE_KEYS: set[str] = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "database_url",
    "connection_string",
    "dsn",
}

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"://[^\s:]+:[^\s@]+@"),
]


def register_pattern(pattern: re.Pattern[str] | str) -> None:
    """Register a regex pattern that :class:`MaskedFormatter` should redact.

    The pattern is appended to the global pattern list and applied on every
    subsequent log record.

    Args:
        pattern: Compiled regex or pattern string. Strings are compiled with
            default flags.
    """
    compiled = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)
    _SECRET_PATTERNS.append(compiled)


def register_sensitive_key(key: str) -> None:
    """Register a key substring that :func:`mask_dict` treats as sensitive.

    Matching is case-insensitive substring against the dict key. The new key
    affects calls that don't pass an explicit ``sensitive_keys`` argument.
    """
    _DEFAULT_SENSITIVE_KEYS.add(key.lower())


def mask(
    value: str,
    *,
    show_first: int = 4,
    show_last: int = 3,
    mask_char: str = "*",
) -> str:
    """Mask a string, preserving only the first and last N characters.

    Args:
        value: The string to mask.
        show_first: Number of leading characters to keep visible.
        show_last: Number of trailing characters to keep visible.
        mask_char: Character used for masking.

    Returns:
        The masked string. If the value is too short to mask meaningfully,
        it is fully replaced with mask characters.
    """
    if not value:
        return value

    length = len(value)
    visible = show_first + show_last

    if length <= visible:
        return mask_char * length

    masked_length = length - visible
    return value[:show_first] + mask_char * masked_length + value[length - show_last :]


def _is_sensitive_key(key: str, sensitive_keys: frozenset[str] | set[str]) -> bool:
    """Check if a key matches any sensitive key via case-insensitive substring match."""
    lower = key.lower()
    return any(s in lower for s in sensitive_keys)


def mask_dict(
    data: dict[str, object],
    *,
    sensitive_keys: frozenset[str] | set[str] | list[str] | None = None,
    show_first: int = 4,
    show_last: int = 3,
) -> dict[str, object]:
    """Recursively mask values whose keys match sensitive key patterns.

    Args:
        data: The dictionary to process.
        sensitive_keys: Key substrings to treat as sensitive. Defaults to a
            built-in set covering common secret field names.
        show_first: Number of leading characters to keep visible in masked values.
        show_last: Number of trailing characters to keep visible in masked values.

    Returns:
        A new dictionary with sensitive string values masked.
    """
    keys: frozenset[str] | set[str]
    if sensitive_keys is None:
        keys = _DEFAULT_SENSITIVE_KEYS
    else:
        keys = frozenset(sensitive_keys)
    return _mask_dict_recursive(data, keys, show_first, show_last)


def _mask_dict_recursive(
    data: dict[str, object],
    sensitive_keys: frozenset[str] | set[str],
    show_first: int,
    show_last: int,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = _mask_dict_recursive(value, sensitive_keys, show_first, show_last)
        elif isinstance(value, str) and _is_sensitive_key(key, sensitive_keys):
            result[key] = mask(value, show_first=show_first, show_last=show_last)
        else:
            result[key] = value
    return result


class MaskedFormatter(logging.Formatter):
    """A logging formatter that automatically masks secret patterns in log messages.

    Detected patterns:
        - ``sk-...`` (OpenAI-style API keys)
        - ``eyJ...`` (JWT tokens)
        - ``AKIA...`` (AWS access key IDs)
        - ``://user:pass@`` (credentials in URLs)

    Usage::

        import logging
        from philiprehberger_masked_print import MaskedFormatter

        handler = logging.StreamHandler()
        handler.setFormatter(MaskedFormatter("%(levelname)s: %(message)s"))
        logger = logging.getLogger(__name__)
        logger.addHandler(handler)
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        message = super().format(record)
        return self._mask_secrets(message)

    @staticmethod
    def _mask_secrets(text: str) -> str:
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(_redact_match, text)
        return text


def _redact_match(m: re.Match[str]) -> str:
    matched = m.group(0)
    if matched.startswith("://"):
        return "://***:***@"
    return mask(matched)
