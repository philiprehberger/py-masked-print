# Changelog

## 0.1.1

- Re-release for PyPI publishing

## 0.1.0 (2026-03-15)

- Initial release
- `mask()` function to mask arbitrary strings with configurable visible prefix/suffix
- `mask_dict()` to recursively mask sensitive keys in dictionaries
- `MaskedFormatter` logging formatter that auto-redacts secret patterns (API keys, JWTs, AWS keys, URL credentials)
