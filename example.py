#!/usr/bin/env python3
"""
Example script demonstrating how to use the Simple Network Scanner as a module.
"""

import sys
from datetime import datetime
from scanner import NetworkScanner
from utils import export_to_json, export_port_scan_to_csv, print_banner

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
            
            # Export results to CSV
            csv_file = export_to_json({"devices": devices}, "discovered_devices.json")
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
            print(f"[+] Results exported to {json_file}")
        
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        sys.exit(1)
    
    print("\n[*] Example completed successfully")

if __name__ == "__main__":
    main()
