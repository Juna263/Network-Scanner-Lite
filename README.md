README.txt

Network Scanner Lite
====================

A lightweight, multi-threaded network port scanner with banner grabbing and risk assessment capabilities.

⚠️ LEGAL DISCLAIMER
-------------------
This tool is for educational purposes and authorized security testing only.
Only scan networks and systems you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction. Use responsibly.

📋 Features
-----------
- Fast concurrent port scanning using thread pools
- Banner grabbing for service identification
- HTTP protocol probing with HEAD requests
- Simple risk scoring based on open services
- JSON and CSV report generation
- Easy-to-use command line interface

🔧 How It Works
---------------

Step 1: Port Scanning
- The tool creates multiple threads (default: 50 workers) to scan ports concurrently
- For each port, it attempts a TCP connection with a configurable timeout (default: 1.5 seconds)
- If connection succeeds (connect_ex returns 0), the port is marked as open

Step 2: Service Detection & Banner Grabbing
- For open ports, the tool attempts to gather additional information:
  - Maps port numbers to common service names (FTP, SSH, HTTP, etc.)
  - Performs banner grabbing by reading initial service response
  - For HTTP ports (80, 8080), sends a HEAD request to get server information

Step 3: Risk Assessment
- Analyzes open ports and assigns a risk score (0-10):
  - High risk (3 points): FTP(21), Telnet(23), SMB(445), RDP(3389), VNC(5900)
  - Medium risk (1 point): SSH(22), HTTP(80), HTTPS(443), POP3(110), IMAP(143)
  - Moderate risk (2 points): All other open ports
- Score is capped at maximum of 10

Step 4: Reporting
- Displays summary results to console
- Optionally exports detailed results to JSON or CSV formats
- JSON format includes full scan metadata and results
- CSV format provides tabular data for easy analysis

🚀 Usage
--------

Basic Syntax:
python3 network_scanner.py --host TARGET [--ports PORTS] [--out-json FILE] [--out-csv FILE]

Examples:

1. Scan default ports on a target:
   python3 network_scanner.py --host example.com

2. Scan specific ports:
   python3 network_scanner.py --host 192.168.1.1 --ports "80,443,8080"

3. Scan port range:
   python3 network_scanner.py --host 10.0.0.1 --ports "20-100"

4. Scan default ports and save reports:
   python3 network_scanner.py --host scanme.nmap.org --out-json report.json --out-csv report.csv

Command Line Options:
--host       Target hostname or IP address (required)
--ports      Ports to scan (default: "default" for common ports)
             Formats: "default", "80,443,8080", "20-100"
--out-json   Output file for JSON report
--out-csv    Output file for CSV report

📊 Output Formats
-----------------

JSON Report Includes:
- Target host and scan timestamp
- Risk score (0-10)
- Detailed results for each port scanned
- Service information and banners

CSV Report Columns:
- host: Target hostname/IP
- timestamp: Scan time
- port: Port number
- open: Boolean indicating if port is open
- service: Detected service name
- banner: Banner text (truncated to 200 chars)

🔍 Default Ports Scanned
------------------------
The tool scans these common ports by default:
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 
80 (HTTP), 110 (POP3), 139 (SMB), 143 (IMAP), 443 (HTTPS),
445 (SMB), 3389 (RDP), 5900 (VNC), 8080 (HTTP-Alt)

📁 File Structure
-----------------
network_scanner.py - Main scanner script
README.txt - This documentation file

🛠️ Requirements
---------------
- Python 3.6+
- No external dependencies - uses only standard library modules

💡 Tips for Effective Use
-------------------------
- Adjust TIMEOUT in the script for slower networks
- Modify DEFAULT_PORTS list for your specific needs
- Use smaller thread counts (workers) for sensitive systems
- Combine with other security tools for comprehensive assessment
- Always verify results manually for critical findings

📝 License
----------
This tool is provided as-is for educational and authorized testing purposes.
Users are responsible for ensuring they have proper authorization before use.

For questions or issues, please check the GitHub repository or create an issue.