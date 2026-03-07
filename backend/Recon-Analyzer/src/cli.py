#!/usr/bin/env python3
"""
ReconGraph CLI - Run scans directly from command line
"""
import argparse
import json
import logging
import re
import socket
import sys

from attack.ipapi import ipapi
from attack.talos import talos
from attack.threatfox import threatfox
from attack.tor import tor
from attack.tranco import tranco
from osint.xposedornot import checkEmail
from osint.phone import validate_phone_number
from osint.username import sagemode_wrapper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

IP_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
URL_REGEX = r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PHONE_REGEX = r'^\+?[0-9]\d{1,14}$'


def print_json(data):
    """Pretty print JSON data."""
    print(json.dumps(data, indent=2))


def scan(query):
    """Scan an IP address or domain."""
    print(f"\n{'='*60}")
    print(f"  SCAN: {query}")
    print(f"{'='*60}\n")
    
    ip_to_scan = None
    url_to_scan = None

    if re.match(IP_REGEX, query):
        ip_to_scan = query
        logger.info(f"Detected IP address: {ip_to_scan}")
    elif re.match(URL_REGEX, query):
        try:
            ip_to_scan = socket.gethostbyname(query)
            url_to_scan = query
            logger.info(f"Detected domain: {query} -> IP: {ip_to_scan}")
        except socket.gaierror as e:
            print(f"ERROR: Unable to resolve domain: {query}")
            return
    else:
        print(f"ERROR: Invalid IP or domain format: {query}")
        return

    results = {"query": query}

    if ip_to_scan:
        print("\n[+] IP API Info...")
        results["ipapi"] = ipapi(ip_to_scan)
        print_json(results["ipapi"])
        
        print("\n[+] Talos Blacklist Check...")
        results["talos"] = talos(ip_to_scan)
        print_json(results["talos"])
        
        print("\n[+] Tor Exit Node Check...")
        results["tor"] = tor(ip_to_scan)
        print_json(results["tor"])

    if url_to_scan:
        print("\n[+] Tranco Ranking...")
        results["tranco"] = tranco(url_to_scan)
        print_json(results["tranco"])
        
        print("\n[+] ThreatFox IOC Check...")
        threatfox_result = threatfox(url_to_scan)
        if threatfox_result:
            results["threatfox"] = threatfox_result
            print_json(results["threatfox"])
        else:
            print("  No IOC found")

    print(f"\n{'='*60}")
    print("  SCAN COMPLETE")
    print(f"{'='*60}\n")


def footprint(query):
    """Analyze digital footprint."""
    print(f"\n{'='*60}")
    print(f"  FOOTPRINT: {query}")
    print(f"{'='*60}\n")

    if re.match(EMAIL_REGEX, query):
        print("[+] Email Breach Check...")
        try:
            result = checkEmail(query)
            print_json(result)
        except Exception as e:
            print(f"  Error: {e}")
            
    elif re.match(PHONE_REGEX, query):
        print("[+] Phone Number Validation...")
        try:
            result = validate_phone_number(query)
            print_json(result)
        except Exception as e:
            print(f"  Error: {e}")
            
    else:
        print("[+] Username Search...")
        print(f"  Searching for '{query}' across platforms...\n")
        try:
            result = sagemode_wrapper(query)
            if result:
                print(f"  Found on {len(result)} site(s):\n")
                for item in result:
                    print(f"  ✓ {item['site']}: {item['url']}")
            else:
                print("  Not found on any platforms")
        except Exception as e:
            print(f"  Error: {e}")

    print(f"\n{'='*60}")
    print("  FOOTPRINT COMPLETE")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ReconGraph - Threat Intelligence & Digital Footprint Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py scan 8.8.8.8
  python cli.py scan google.com
  python cli.py footprint test@example.com
  python cli.py footprint +14155552671
  python cli.py footprint ClstDegen
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan IP or domain for threat intelligence')
    scan_parser.add_argument('query', help='IP address or domain to scan')
    
    # Footprint command
    footprint_parser = subparsers.add_parser('footprint', help='Analyze digital footprint')
    footprint_parser.add_argument('query', help='Email, phone number, or username')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scan(args.query)
    elif args.command == 'footprint':
        footprint(args.query)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("        ReconGraph - CLI Mode")
    print("="*60)
    main()
