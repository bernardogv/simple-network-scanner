#!/usr/bin/env python3
"""
Utility functions for the Simple Network Scanner.
"""

import os
import sys
import json
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# Try to import required modules, with helpful error messages
try:
    import ipaddress
except ImportError:
    print("Error: ipaddress module not found. Please run 'pip install ipaddress' or 'pip3 install ipaddress'")
    print("If you're using Homebrew Python, you may need to use: /opt/homebrew/bin/pip3 install ipaddress")
    sys.exit(1)


def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate if a string is a valid CIDR notation.
    
    Args:
        cidr: String to validate
        
    Returns:
        True if valid CIDR notation, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse a port range string into a list of port numbers.
    
    Args:
        port_str: Port range string (e.g., "22,80,443" or "1-1000")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    # Split by comma
    parts = port_str.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Check if it's a range (e.g., "1-1000")
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            # Single port
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    return sorted(list(set(ports)))


def export_to_json(data: Dict[str, Any], filename: Optional[str] = None) -> str:
    """
    Export scan results to a JSON file.
    
    Args:
        data: Scan results to export
        filename: Output filename (optional)
        
    Returns:
        Path to the created file
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] Results exported to {filename}")
        return os.path.abspath(filename)
    except Exception as e:
        print(f"[!] Error exporting to JSON: {e}")
        return ""


def export_to_csv(hosts: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
    """
    Export discovered hosts to a CSV file.
    
    Args:
        hosts: List of discovered hosts
        filename: Output filename (optional)
        
    Returns:
        Path to the created file
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"discovered_hosts_{timestamp}.csv"
    
    fieldnames = ['ip', 'mac', 'hostname']
    
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(hosts)
        print(f"[+] Host data exported to {filename}")
        return os.path.abspath(filename)
    except Exception as e:
        print(f"[!] Error exporting to CSV: {e}")
        return ""


def export_port_scan_to_csv(results: Dict[str, Any], filename: Optional[str] = None) -> str:
    """
    Export port scan results to a CSV file.
    
    Args:
        results: Port scan results
        filename: Output filename (optional)
        
    Returns:
        Path to the created file
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"port_scan_{timestamp}.csv"
    
    rows = []
    
    # Process the results
    for ip, host_data in results.get('hosts', {}).items():
        if host_data.get('status') != 'up':
            continue
        
        for port, port_data in host_data.get('ports', {}).items():
            rows.append({
                'ip': ip,
                'port': port,
                'state': port_data.get('state', ''),
                'service': port_data.get('service', ''),
                'product': port_data.get('product', ''),
                'version': port_data.get('version', '')
            })
    
    if not rows:
        print("[!] No port scan data to export")
        return ""
    
    fieldnames = ['ip', 'port', 'state', 'service', 'product', 'version']
    
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Port scan data exported to {filename}")
        return os.path.abspath(filename)
    except Exception as e:
        print(f"[!] Error exporting to CSV: {e}")
        return ""


def print_banner() -> None:
    """Print the application banner."""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║                                           ║
    ║         SIMPLE NETWORK SCANNER            ║
    ║                                           ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)
