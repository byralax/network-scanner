#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, TCP, IP, sr1, ICMP
import ipaddress
import argparse
from datetime import datetime
import json
import csv
import nmap
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import socket

class NetworkScanner:
    def __init__(self, network: str, ports: List[int] = None):
        """
        Initialize the enhanced scanner
        :param network: Network address in CIDR notation (e.g., '192.168.1.0/24')
        :param ports: List of ports to scan. Default is common ports
        """
        self.network = network
        self.ports = ports or [21, 22, 23, 25, 80, 443, 445, 3389, 8080]  # Common ports
        self.nm = nmap.PortScanner()  # Initialize nmap scanner
        
    def scan_ports(self, ip: str) -> Dict[int, str]:
        """
        Scan ports for a specific IP address
        :param ip: IP address to scan
        :return: Dictionary of port numbers and their states
        """
        open_ports = {}
        for port in self.ports:
            try:
                # Create a TCP SYN packet
                syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
                # Send packet and wait for response
                response = sr1(syn_packet, timeout=1, verbose=0)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK received
                        # Send RST packet to close connection
                        rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                        sr1(rst_packet, timeout=1, verbose=0)
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        open_ports[port] = service
            except Exception as e:
                print(f"Error scanning port {port}: {str(e)}")
                
        return open_ports

    def detect_os(self, ip: str) -> Dict[str, Any]:
        """
        Detect operating system using nmap
        :param ip: IP address to fingerprint
        :return: Dictionary containing OS detection results
        """
        try:
            self.nm.scan(ip, arguments='-O')
            if 'osmatch' in self.nm[ip]:
                os_matches = self.nm[ip]['osmatch']
                if os_matches:
                    return {
                        'os_name': os_matches[0]['name'],
                        'accuracy': os_matches[0]['accuracy'],
                        'type': os_matches[0].get('osclass', [{}])[0].get('type', 'unknown')
                    }
        except Exception as e:
            print(f"OS detection error for {ip}: {str(e)}")
        return {'os_name': 'Unknown', 'accuracy': 0, 'type': 'unknown'}

    def detect_services(self, ip: str, ports: Dict[int, str]) -> Dict[int, Dict[str, str]]:
        """
        Detect services running on open ports
        :param ip: IP address
        :param ports: Dictionary of open ports
        :return: Dictionary of port numbers and service information
        """
        service_info = {}
        try:
            for port in ports:
                self.nm.scan(ip, str(port))
                if ip in self.nm.all_hosts():
                    service_data = self.nm[ip].get('tcp', {}).get(port, {})
                    service_info[port] = {
                        'service': service_data.get('name', 'unknown'),
                        'version': service_data.get('version', 'unknown'),
                        'product': service_data.get('product', 'unknown')
                    }
        except Exception as e:
            print(f"Service detection error for {ip}: {str(e)}")
        return service_info

    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform complete network scan including ARP, ports, OS, and services
        :return: List of dictionaries containing all scan results
        """
        # Create ARP request packet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.network)
        print(f"\n[*] Starting comprehensive scan of network: {self.network}")
        
        answered, _ = srp(arp_request, timeout=2, verbose=False)
        devices = []

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            
            print(f"\n[*] Scanning {ip}...")
            
            # Scan ports
            open_ports = self.scan_ports(ip)
            print(f"[+] Found {len(open_ports)} open ports on {ip}")
            
            # Detect OS
            os_info = self.detect_os(ip)
            print(f"[+] OS Detection for {ip}: {os_info['os_name']} ({os_info['accuracy']}% accuracy)")
            
            # Detect services
            services = self.detect_services(ip, open_ports)
            print(f"[+] Detected {len(services)} services on {ip}")

            devices.append({
                'ip': ip,
                'mac': mac,
                'open_ports': open_ports,
                'os_info': os_info,
                'services': services
            })
            
        return devices

    def save_results(self, devices: List[Dict[str, Any]], output_format: str, filename: str):
        """
        Save scan results to file in specified format
        :param devices: List of scan results
        :param output_format: Format to save in ('json' or 'csv')
        :param filename: Output filename
        """
        if output_format == 'json':
            with open(filename, 'w') as f:
                json.dump(devices, f, indent=4)
        
        elif output_format == 'csv':
            # Flatten the nested structure for CSV
            flattened_data = []
            for device in devices:
                base_info = {
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'os': device['os_info']['os_name'],
                    'os_accuracy': device['os_info']['accuracy']
                }
                
                # Add port and service information
                for port, service in device['services'].items():
                    row = base_info.copy()
                    row.update({
                        'port': port,
                        'service': service['service'],
                        'version': service['version'],
                        'product': service['product']
                    })
                    flattened_data.append(row)
            
            # Write CSV file
            if flattened_data:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened_data)

def main():
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner')
    parser.add_argument('-n', '--network', required=True,
                        help='Network to scan (CIDR notation, e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', type=str,
                        help='Comma-separated list of ports to scan (e.g., "80,443,8080")')
    parser.add_argument('-o', '--output', choices=['json', 'csv'],
                        help='Output format (json or csv)')
    parser.add_argument('-f', '--filename',
                        help='Output filename')
    
    args = parser.parse_args()

    try:
        # Validate network address
        ipaddress.ip_network(args.network)
        
        # Parse ports if provided
        ports = None
        if args.ports:
            ports = [int(p) for p in args.ports.split(',')]
        
        # Record start time
        start_time = datetime.now()
        
        # Create scanner instance and run scan
        scanner = NetworkScanner(args.network, ports)
        discovered_devices = scanner.scan()
        
        # Calculate scan duration
        duration = datetime.now() - start_time
        
        # Save results if output format specified
        if args.output and args.filename:
            scanner.save_results(discovered_devices, args.output, args.filename)
            print(f"\n[*] Results saved to {args.filename}")
        
        print(f"\n[*] Scan completed in {duration.total_seconds():.2f} seconds")
        print(f"[*] Found {len(discovered_devices)} devices")
        
    except ValueError as e:
        print(f"Error: Invalid network address. {str(e)}")
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    # Check for root/admin privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    main()
