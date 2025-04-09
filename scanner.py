#!/usr/bin/env python3
"""
Simple Network Scanner
A lightweight Python tool for basic network scanning and discovery.
"""

import argparse
import ipaddress
import socket
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Tuple

try:
    import nmap
    from scapy.all import ARP, Ether, srp
    from colorama import Fore, Style, init
except ImportError:
    print("Error: Required libraries not found. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

# Initialize colorama
init()

class NetworkScanner:
    """Network scanning utility with various scanning capabilities."""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_network(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan a network range to discover active hosts.
        
        Args:
            target: IP address or network range in CIDR notation
        
        Returns:
            List of discovered hosts with their MAC addresses
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            print(f"{Fore.BLUE}[*] Scanning network: {target}{Style.RESET_ALL}")
            
            # Create ARP request packet
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            start_time = datetime.now()
            result = srp(packet, timeout=3, verbose=0)[0]
            end_time = datetime.now()
            
            # Process responses
            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            
            # Print results
            print(f"{Fore.GREEN}[+] Scan completed in {(end_time - start_time).total_seconds():.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found {len(devices)} active devices{Style.RESET_ALL}")
            
            return devices
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning network: {e}{Style.RESET_ALL}")
            return []
    
    def scan_ports(self, target: str, ports: str, service_detection: bool = False) -> Dict[str, Any]:
        """
        Scan ports on a specific target.
        
        Args:
            target: IP address to scan
            ports: Port range (e.g., "22,80,443" or "1-1000")
            service_detection: Whether to detect services running on open ports
        
        Returns:
            Dictionary with scan results
        """
        try:
            print(f"{Fore.BLUE}[*] Scanning ports {ports} on {target}{Style.RESET_ALL}")
            
            # Arguments for nmap scan
            arguments = f"-p {ports}"
            if service_detection:
                arguments += " -sV"
            
            # Perform scan
            start_time = datetime.now()
            self.nm.scan(hosts=target, arguments=arguments)
            end_time = datetime.now()
            
            # Process results
            result = {
                'scan_time': (end_time - start_time).total_seconds(),
                'hosts': {}
            }
            
            # Check if target was scanned successfully
            if target in self.nm.all_hosts():
                host_data = self.nm[target]
                result['hosts'][target] = {
                    'status': host_data.state(),
                    'ports': {}
                }
                
                # Add port information
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        result['hosts'][target]['ports'][port] = {
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', '')
                        }
            
            # Print results
            print(f"{Fore.GREEN}[+] Port scan completed in {result['scan_time']:.2f} seconds{Style.RESET_ALL}")
            if target in result['hosts']:
                open_ports = [port for port, data in result['hosts'][target]['ports'].items() 
                             if data['state'] == 'open']
                print(f"{Fore.GREEN}[+] Found {len(open_ports)} open ports{Style.RESET_ALL}")
            
            return result
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning ports: {e}{Style.RESET_ALL}")
            return {'scan_time': 0, 'hosts': {}}
    
    def get_hostname(self, ip: str) -> str:
        """
        Get hostname for an IP address.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Hostname or empty string if not found
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ""

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument("--target", required=True, help="Target IP address or network range (CIDR notation)")
    parser.add_argument("--ports", default="1-1024", help="Port range to scan (e.g., '22,80,443' or '1-1000')")
    parser.add_argument("--service-detection", action="store_true", help="Enable service detection")
    return parser.parse_args()

def print_devices(devices: List[Dict[str, Any]], scanner: NetworkScanner) -> None:
    """Print discovered devices in a table format."""
    if not devices:
        return
    
    # Print header
    print("\nDiscovered devices:")
    print(f"{Fore.CYAN}{'IP Address':<16} {'MAC Address':<18} {'Hostname':<30}{Style.RESET_ALL}")
    print("-" * 64)
    
    # Print each device
    for device in devices:
        hostname = scanner.get_hostname(device['ip'])
        print(f"{device['ip']:<16} {device['mac']:<18} {hostname:<30}")
    
    print()

def print_port_scan_results(results: Dict[str, Any]) -> None:
    """Print port scan results in a table format."""
    if not results['hosts']:
        return
    
    for ip, host_data in results['hosts'].items():
        if host_data['status'] != 'up' or not host_data['ports']:
            continue
        
        # Print header
        print(f"\nOpen ports for {ip}:")
        print(f"{Fore.CYAN}{'Port':<8} {'State':<10} {'Service':<15} {'Version'}{Style.RESET_ALL}")
        print("-" * 70)
        
        # Print each port
        for port, port_data in host_data['ports'].items():
            if port_data['state'] == 'open':
                version_info = f"{port_data['product']} {port_data['version']}".strip()
                print(f"{port:<8} {port_data['state']:<10} {port_data['service']:<15} {version_info}")
        
        print()

def main() -> None:
    """Main function."""
    args = parse_arguments()
    scanner = NetworkScanner()
    
    print(f"{Fore.YELLOW}[*] Starting Simple Network Scanner at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Target: {args.target}{Style.RESET_ALL}")
    
    try:
        # Determine if target is a single IP or a network range
        target = args.target.strip()
        is_network = '/' in target
        
        # If target is a network, scan for devices first
        devices = []
        if is_network:
            devices = scanner.scan_network(target)
            print_devices(devices, scanner)
        
        # If target is a single IP or if devices were found in network scan
        if not is_network or devices:
            # For network scan, only scan discovered devices
            targets = [device['ip'] for device in devices] if is_network else [target]
            
            # Scan ports on each target
            for target_ip in targets:
                results = scanner.scan_ports(target_ip, args.ports, args.service_detection)
                print_port_scan_results(results)
        
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
