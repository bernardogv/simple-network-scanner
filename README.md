# Simple Network Scanner

A lightweight Python tool for basic network scanning and discovery.

## Features

- IP range scanning
- Port scanning
- Host discovery
- Service identification
- Simple and clean CLI interface

## Installation

### Method 1: Standard Installation

```bash
# Clone the repository
git clone https://github.com/bernardogv/simple-network-scanner.git

# Navigate to the project directory
cd simple-network-scanner

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Using a Virtual Environment (Recommended)

```bash
# Clone the repository
git clone https://github.com/bernardogv/simple-network-scanner.git

# Navigate to the project directory
cd simple-network-scanner

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies in the virtual environment
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single IP address
python scanner.py --target 192.168.1.1

# Scan an IP range
python scanner.py --target 192.168.1.0/24

# Scan specific ports
python scanner.py --target 192.168.1.1 --ports 22,80,443

# Perform a more comprehensive scan
python scanner.py --target 192.168.1.0/24 --ports 1-1000 --service-detection
```

## Troubleshooting

If you encounter permission issues when running scans (especially on Linux/macOS):

```bash
# Use sudo to run with elevated privileges
sudo python scanner.py --target 192.168.1.1
```

For macOS with Homebrew Python, if you have import issues:

```bash
# Use the specific Python interpreter
/opt/homebrew/bin/python3 scanner.py --target 192.168.1.1

# Or install requirements with specific pip
/opt/homebrew/bin/pip3 install -r requirements.txt
```

## Requirements

- Python 3.6+
- scapy
- python-nmap
- ipaddress
- colorama

## License

MIT
