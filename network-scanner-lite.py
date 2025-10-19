#!/usr/bin/env python3
"""
Network Scanner Lite
- Scans ports (using concurrent threads) which is faster
- Performs simple banner grabs and minimal protocol probes (with just an HTTP HEAD request)
- Produces JSON/CSV report and assigns a simple risk score.

This tool is designed to be easy to use and perform simple port scanning and banner grabbing.
"""

import socket
import concurrent.futures
import argparse
import json
import csv
import time

#CONFIGURATION
#Default ports to scan if none are specified by the user
DEFAULT_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3389,5900,8080]

#Mapping of the ports to their services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "SMB", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP-ALT"
}

#TIMEOUT FOR SOCKET OPERATIONS 
TIMEOUT = 1.5

# HELPERS.
def try_connect(host, port, timeout=TIMEOUT):
##  THIS WILL ATTEMPT A CONNECTION TO A HOST/PORT AND RETURN AN OPEN SOCKET IF SUCCESSFUL OTHERWISE NOTHING.

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((host, port))  # returns 0 if connection succeeds
        if code == 0:
            return s  # return the socket so it can be used for banner grabbing
    except Exception:
        pass
    # Always close socket if not usable
    try:
        s.close()
    except:
        pass
    return None

def banner_grab(sock, host, port):
##  try and grab a banner from an open socket.
##  if its HTTP, send a HEAD request if not just read available data
    try:
        sock.settimeout(1.0)
        # Special probe for HTTP services
        if port in (80, 8080):
            request = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode()
            sock.sendall(request)
        # Attempt to receive any available response (banner)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""
    finally:
        # Ensure socket is closed
        try:
            sock.close()
        except:
            pass

def scan_port(host, port):
    """Scan a single port. 
    Return details: open/closed, service name, and banner (if any)."""
    s = try_connect(host, port)
    if s:
        banner = banner_grab(s, host, port)
        service = COMMON_SERVICES.get(port, "unknown")
        return {"port": port, "open": True, "service": service, "banner": banner}
    return {"port": port, "open": False, "service": None, "banner": None}

def risk_for_ports(results):
##  CALCULATE RISK SCORE DEPENDING ON WHICH PORTS ARE OPEN, SOME PORTS ARE MORE DANGEROUS THAN OTHERS.
    risk = 0
    for r in results:
        if not r["open"]:
            continue
        p = r["port"]
        # High-risk ports (FTP, Telnet, SMB, RDP, VNC)
        if p in (21,23,445,3389,5900): 
            risk += 3
        # Medium-risk ports (SSH, HTTP, HTTPS, POP3, IMAP)
        elif p in (22,80,443,110,143): 
            risk += 1
        # Everything else is moderate risk
        else: 
            risk += 2
    # Cap the score at 10
    return min(risk, 10)

def scan_host(host, ports, workers=50):
##  SCAN MULTIPLE PORTS USING CONCURRENT THREADS AND RETURN A FULL RISK SCORE
    results = []
    # Use ThreadPoolExecutor to scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                r = fut.result()  # Get result of scan_port()
            except Exception as e:
                # In case of failure, mark port as closed
                r = {"port": futures[fut], "open": False, "service": None, "banner": None}
            results.append(r)
    # Sort results by port number
    results.sort(key=lambda x: x["port"])
    return {
        "host": host,
        "timestamp": time.time(),
        "results": results,
        "risk_score": risk_for_ports(results)
    }

def export_json(report, filename):
    #   EXPORT TO A JSON FILE.
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def export_csv(report, filename):
    #   EXPORT TO A CSV FILE.
    rows = []
    for r in report["results"]:
        rows.append([
            report["host"], report["timestamp"], r["port"], 
            r["open"], r["service"], (r["banner"] or "")[:200]
        ])
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        # Write header row
        writer.writerow(["host","timestamp","port","open","service","banner"])
        writer.writerows(rows)

# COMMAND LINE INTERFACE
if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Scanner Lite (ethical use only)")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", default="default", help="Ports: e.g. '20-1024' or '80,443,8080' or 'default'")
    parser.add_argument("--out-json", help="Write JSON report")
    parser.add_argument("--out-csv", help="Write CSV report")
    args = parser.parse_args()

    # Determine which ports to scan
    if args.ports == "default":
        ports = DEFAULT_PORTS
    elif "-" in args.ports:
        # Range of ports
        a, b = args.ports.split("-")
        ports = list(range(int(a), int(b)+1))
    else:
        # Comma-separated list of ports
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    # Perform scan
    report = scan_host(args.host, ports)

    # Print summary to console
    print(f"Host: {report['host']}  Risk score: {report['risk_score']}/10")
    for r in report['results']:
        if r['open']:
            print(f"  Port {r['port']}: OPEN ({r['service']}) Banner: { (r['banner'][:120] + '...') if r['banner'] else 'none' }")

    # Save reports if requested
    if args.out_json:
        export_json(report, args.out_json)
        print("JSON written:", args.out_json)
    if args.out_csv:
        export_csv(report, args.out_csv)
        print("CSV written:", args.out_csv)
