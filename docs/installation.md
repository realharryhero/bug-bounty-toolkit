# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Virtual Browser (Optional)
For the virtual browser environment, you also need:
- Docker 20.10 or higher
- Docker Compose 2.0 or higher
- At least 4GB of available RAM
- 10GB of available disk space

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/realharryhero/bug-bounty-toolkit.git
cd bug-bounty-toolkit
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python main.py --help
```

You should see the help message with available options.

### 5. Install Virtual Browser (Optional)

If you want to use the virtual browser environment:

#### On Ubuntu/Debian:
```bash
# Install Docker
sudo apt-get update
sudo apt-get install docker.io docker-compose-plugin
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

#### On macOS:
```bash
# Install Docker Desktop
brew install --cask docker
# Or download from https://www.docker.com/products/docker-desktop
```

#### On Windows:
- Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
- Enable WSL 2 if prompted

#### Start Virtual Browser:
```bash
./start-virtual-browser.sh

# Or on Windows:
start-virtual-browser.bat

# Or using make:
make start
```

Access the virtual browser at: http://localhost:6080

For detailed virtual browser documentation, see [VIRTUAL_BROWSER.md](../VIRTUAL_BROWSER.md)

## Optional Dependencies

For enhanced functionality, you may want to install additional packages:

### PDF Report Generation
```bash
pip install weasyprint reportlab
```

### Advanced Network Operations
```bash
pip install aiohttp dnspython
```

### Enhanced SSL/TLS Analysis
```bash
pip install pyopenssl
```

## Configuration

1. Copy the default configuration:
   ```bash
   cp config/default.yml config/my_config.yml
   ```

2. Edit the configuration file to match your needs

3. Use your custom configuration:
   ```bash
   python main.py --config config/my_config.yml --scan sqli --target https://example.com
   ```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you have proper permissions to install packages
2. **Module Not Found**: Verify virtual environment is activated
3. **Network Timeouts**: Check your internet connection and proxy settings

### Getting Help

If you encounter issues:
1. Check the error message carefully
2. Review the documentation in the `docs/` directory
3. Create an issue on GitHub with detailed error information