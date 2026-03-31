# philiprehberger-masked-print

[![Tests](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-masked-print.svg)](https://pypi.org/project/philiprehberger-masked-print/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-masked-print)](https://github.com/philiprehberger/py-masked-print/commits/main)

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
| `mask_dict(data, *, sensitive_keys=None, show_first=4, show_last=3)` | Recursively mask sensitive key values in a dictionary |
| `MaskedFormatter(fmt)` | Logging formatter that auto-redacts secret patterns (sk-..., eyJ..., AKIA..., URL credentials) |

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
