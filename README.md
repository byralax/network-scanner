# network-scanner
This network scanner implements several important security and networking concepts:

ARP (Address Resolution Protocol): Used to discover active hosts on the local network by sending broadcast requests.
Object-Oriented Design: Uses a NetworkScanner class to encapsulate scanning functionality.
Error Handling: Includes proper exception handling for invalid inputs and network errors.
Command Line Interface: Uses argparse for proper command-line argument handling.
Performance Monitoring: Tracks and reports scan duration.

To use this scanner:

First install the required library:

bash: pip install scapy

Run the script with sudo/administrator privileges (required for raw socket access):
bash: sudo python3 scanner.py -n 192."ip"

This enhanced version includes several new features and improvements:

Port Scanning:

Uses TCP SYN scanning for port detection
Configurable port list via command line
Service name resolution for open ports


OS Fingerprinting:

Uses nmap's OS detection capabilities
Provides OS name, accuracy, and system type
Handles cases where OS detection fails gracefully


Service Detection:

Identifies services running on open ports
Attempts to determine service versions
Includes product information when available


Multiple Output Formats:

JSON output for full detail and nested data
CSV output for easy spreadsheet analysis
Structured data format for both


To use this enhanced scanner, you'll need additional dependencies:
bash: pip install python-nmap scapy

Important security notes:

This tool performs more intensive scanning than the previous version and is more likely to be detected by security systems
OS fingerprinting and service detection may trigger security alerts
Some networks may block these types of scans
Always ensure you have permission to perform these scans on the target network
