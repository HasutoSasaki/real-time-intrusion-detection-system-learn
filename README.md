# real-time-intrusion-detection-system-learn

Real-time intrusion detection system using machine learning and network packet analysis.

## Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) - Fast Python package installer and resolver
- For packet capture: root/administrator privileges may be required

## Setup

### 1. Install uv (if not already installed)

```bash
# macOS/Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows:
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or with pip:
pip install uv
```

### 2. Clone the repository

```bash
git clone <repository-url>
cd real-time-intrusion-detection-system-learn
```

### 3. Install dependencies

```bash
# uv automatically creates a virtual environment and installs dependencies
uv sync
```

That's it! `uv` will create a `.venv` directory and install all dependencies from `pyproject.toml`.

## Dependencies

- **scapy**: Network packet manipulation and analysis
- **python-nmap**: Network scanning and port detection
- **numpy**: Numerical computing for data processing
- **scikit-learn**: Machine learning algorithms for intrusion detection

All dependencies are managed in [pyproject.toml](pyproject.toml).

## Usage

```bash
# Run with uv (automatically uses the virtual environment)
uv run python main.py

# Or activate the virtual environment manually
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Then run your script
python main.py
```

## Development

### Adding new dependencies

```bash
# Add a new package
uv add <package-name>

# Add a development dependency
uv add --dev <package-name>
```

### Removing dependencies

```bash
uv remove <package-name>
```

### Updating dependencies

```bash
# Update all dependencies
uv sync --upgrade

# Update a specific package
uv add <package-name> --upgrade
```

## Security Notes

- This system requires network packet capture capabilities
- Run with appropriate permissions (may require sudo/admin rights)
- Only use on networks you have permission to monitor
- Never commit sensitive data or API keys to the repository

## Why uv?

- **Fast**: 10-100x faster than pip
- **Reliable**: Built-in dependency resolver prevents conflicts
- **Modern**: Uses `pyproject.toml` standard
- **Simple**: Automatic virtual environment management

## License

This project is for educational purposes.
