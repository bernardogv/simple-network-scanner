# Simple Network Scanner

A lightweight Python tool for basic network scanning and discovery.

## Features

- IP range scanning
- Port scanning
- Host discovery
- Service identification
- Simple and clean CLI interface

## Installation

```bash
# Clone the repository
git clone https://github.com/bernardogv/simple-network-scanner.git

# Navigate to the project directory
cd simple-network-scanner

# Install dependencies
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

## Requirements

- Python 3.6+
- scapy
- python-nmap

## License

MIT
