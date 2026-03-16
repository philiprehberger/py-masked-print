# philiprehberger-masked-print

[![Tests](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-masked-print/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-masked-print.svg)](https://pypi.org/project/philiprehberger-masked-print/)
[![License](https://img.shields.io/github/license/philiprehberger/py-masked-print)](LICENSE)

Automatically mask sensitive values (API keys, passwords, tokens) in logs and print output.

## Install

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

## License

MIT
