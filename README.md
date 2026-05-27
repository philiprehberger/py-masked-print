# philiprehberger-masked-print

[![Tests](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-masked-print.svg)](https://pypi.org/project/philiprehberger-masked-print/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-masked-print)](https://github.com/philiprehberger/py-masked-print/commits/main)

![philiprehberger-masked-print](https://raw.githubusercontent.com/philiprehberger/py-masked-print/main/package-card.webp)

Automatically mask sensitive values (API keys, passwords, tokens) in logs and print output.

## Installation

```bash
pip install philiprehberger-masked-print
```

## Usage

```python
from philiprehberger_masked_print import mask, mask_dict, MaskedFormatter

# Mask a single string
masked = mask("sk-abc123secret456xyz")
# "sk-a*************xyz"
```

### Mask dictionaries

```python
config = {
    "host": "localhost",
    "password": "super-secret-value",
    "database": {
        "connection_string": "postgres://admin:pass@localhost/db",
    },
}

safe = mask_dict(config)
# {
#     "host": "localhost",
#     "password": "supe***********lue",
#     "database": {
#         "connection_string": "post*****************/db",
#     },
# }
```

### Target nested keys with path globs

`mask_dict()` accepts dotted path globs to mask specific nested fields without touching the default key heuristics.

```python
config = {
    "database": {
        "primary":   {"host": "db1", "password": "p1"},
        "replica":   {"host": "db2", "password": "p2"},
    },
    "auth": {"public_key": "pk", "token": "tk"},
}

safe = mask_dict(
    config,
    paths=["database.*.password", "auth.token"],
)
# database.primary.password and database.replica.password are masked
# auth.token is masked; auth.public_key is left alone
```

A `*` in a path glob matches a single segment. Path matching runs in addition to the default `sensitive_keys` matching, so both rule sets compose.

### Extend defaults at runtime

```python
from philiprehberger_masked_print import register_pattern, register_sensitive_key

# Add a domain-specific secret pattern picked up by MaskedFormatter
register_pattern(r"PINPIN-\d{4,}")

# Add a custom key that mask_dict should treat as sensitive
register_sensitive_key("session_id")
```

### Auto-mask log output

```python
import logging
from philiprehberger_masked_print import MaskedFormatter

handler = logging.StreamHandler()
handler.setFormatter(MaskedFormatter("%(levelname)s: %(message)s"))

logger = logging.getLogger("app")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

logger.info("Using key sk-proj-abc123def456ghi789jkl012mno")
# INFO: Using key sk-p*************************mno
```

## API

| Function / Class | Description |
|---|---|
| `mask(value, *, show_first=4, show_last=3, mask_char="*")` | Mask a string, keeping the first and last N characters visible |
| `mask_dict(data, *, sensitive_keys=None, paths=None, show_first=4, show_last=3)` | Recursively mask sensitive key values; `paths` targets nested keys with dotted globs like `"database.*.password"` |
| `MaskedFormatter(fmt)` | Logging formatter that auto-redacts secret patterns (sk-..., eyJ..., AKIA..., URL credentials) |
| `register_pattern(pattern)` | Register an extra regex pattern for `MaskedFormatter` to redact |
| `register_sensitive_key(key)` | Add a key substring to the default sensitive-key set used by `mask_dict` |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/py-masked-print)

🐛 [Report issues](https://github.com/philiprehberger/py-masked-print/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/py-masked-print/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
