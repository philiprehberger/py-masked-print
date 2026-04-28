# Changelog

## 0.2.0 (2026-04-27)

- Add `register_pattern(pattern)` to register additional regex patterns that `MaskedFormatter` should redact
- Add `register_sensitive_key(key)` to extend the default sensitive-key set used by `mask_dict()`
- Replace 7-line import-only test with a comprehensive test suite covering `mask`, `mask_dict`, all 4 built-in `MaskedFormatter` patterns, and the new registration APIs
- Repair malformed CHANGELOG entry from previous release

## 0.1.7 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.1.6 (2026-03-29)

- Add pytest and mypy tool configuration to pyproject.toml

## 0.1.5 (2026-03-22)

- Add basic import test

## 0.1.4 (2026-03-19)

- Add Development section to README

## 0.1.1 (2026-03-17)

- Re-release for PyPI publishing

## 0.1.0 (2026-03-15)

- Initial release
- `mask()` function to mask arbitrary strings with configurable visible prefix/suffix
- `mask_dict()` to recursively mask sensitive keys in dictionaries
- `MaskedFormatter` logging formatter that auto-redacts secret patterns (API keys, JWTs, AWS keys, URL credentials)
