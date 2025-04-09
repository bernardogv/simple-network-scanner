#!/usr/bin/env python3
"""
Example script demonstrating how to use the Simple Network Scanner as a module.
"""

import sys
import os
from datetime import datetime

# Ensure all modules can be imported
try:
    from scanner import NetworkScanner
    from utils import export_to_json, export_port_scan_to_csv, print_banner
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you're running this script from the project directory and have installed all requirements.")
    print("Try: pip install -r requirements.txt")
    
    # Check if the user is using Homebrew Python and provide additional guidance
    if "HOMEBREW" in os.environ.get("PATH", "") or "/opt/homebrew" in os.environ.get("PATH", ""):
        print("\nNOTE: It appears you're using Homebrew Python. You might need to use:")
        print("python3 -m pip install -r requirements.txt")
        print("Or: /opt/homebrew/bin/pip3 install -r requirements.txt")
    
    sys.exit(1)

def main():
    """Run an example network scan."""
    print_banner()
    print(f"Example scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create a scanner instance
    scanner = NetworkScanner()
    
    # Example 1: Scan a local network
    target_network = "192.168.1.0/24"  # Change to your network
    print(f"\n[*] Example 1: Scanning network {target_network}")
    
    try:
        # Discover devices on the network
        devices = scanner.scan_network(target_network)
        
        if devices:
            print(f"[+] Found {len(devices)} active devices")
            
            # Export results to JSON
            csv_file = export_to_json({"devices": devices}, "discovered_devices.json")
            if csv_file:
                print(f"[+] Results exported to {csv_file}")
            
            # Example 2: Scan ports on the first discovered device
            if devices:
                target_ip = devices[0]['ip']
                print(f"\n[*] Example 2: Scanning common ports on {target_ip}")
                
                # Scan common ports
                port_results = scanner.scan_ports(target_ip, "22,80,443,3389,8080", service_detection=True)
                
                # Export results to CSV
                if port_results['hosts']:
                    csv_file = export_port_scan_to_csv(port_results, "port_scan_results.csv")
                    if csv_file:
                        print(f"[+] Port scan results exported to {csv_file}")
        else:
            print("[!] No devices found on the network")
            
            # Example 3: Scan a specific target instead
            target_ip = "8.8.8.8"  # Google DNS
            print(f"\n[*] Example 3: Scanning specific target {target_ip}")
            
            # Scan some common ports
            port_results = scanner.scan_ports(target_ip, "53,80,443", service_detection=True)
            
            # Export results to JSON
            json_file = export_to_json(port_results, "external_scan_results.json")
            if json_file:
                print(f"[+] Results exported to {json_file}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        print("[!] If this is related to permission issues, try running with sudo/administrator privileges")
        sys.exit(1)
    
    print("\n[*] Example completed successfully")

if __name__ == "__main__":
    # Check if running with appropriate privileges for network scanning
    if os.name == 'posix' and os.geteuid() != 0:
        print("[!] Warning: This script may need root privileges to perform network scans")
        print("[!] Consider running with sudo if you encounter permission errors")
    
    main()
