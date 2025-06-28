# UFWInspector

A UFW log analyzer for security monitoring.

## Features

- Analyzes UFW logs from `/var/log/ufw.log`
- Groups events by type (UFW_BLOCK, UFW_AUDIT, etc.)
- Deduplicates entries by IP address
- Resolves domain names for IP addresses
- Identifies whether public addresses are source or destination
- Presents results in a sorted table by number of occurrences

## Installation

### From Package (Ubuntu)

```bash
sudo apt install ./ufwinspector_0.1.0_all.deb
```

### From Source

```bash
pip install .
```

## Usage

```bash
# Analyze UFW logs
ufwinspector analyze

# Show help
ufwinspector --help
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Check code quality
mypy ufwinspector
black ufwinspector
isort ufwinspector
flake8 ufwinspector
```

## License

MIT
