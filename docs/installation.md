# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

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