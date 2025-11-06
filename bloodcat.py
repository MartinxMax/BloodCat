#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

import socket
import base64
import argparse
from lib.camlib import * 
from lib.fofaget import * 

LOGO = r'''
                  ;,_            ,
                 _uP~"b          d"u,
                dP'   "b       ,d"  "o
               d"    , `b     d"'    "b
              l] [    " `l,  d"       lb
              Ol ?     "  "b`"=uoqo,_  "l
            ,dBb "b        "b,    `"~~TObup,_
          ,d" (db.`"         ""     "tbc,_ `~"Yuu,_
        .d" l`T'  '=                      ~     `""Yu,
      ,dO` gP,                           `u,   b,_  "b7
     d?' ,d" l,                           `"b,_ `~b  "1
   ,8i' dl   `l                 ,ggQOV",dbgq,._"  `l  lb
  .df' (O,    "             ,ggQY"~  , @@@@@d"bd~  `b "1
 .df'   `"           -=@QgpOY""     (b  @@@@P db    `Lp"b,
.d(                  _               "ko "=d_,Q`  ,_  "  "b,
Ql         .         `"qo,._          "tQo,_`""bo ;tb,    `"b,
qQ         |L           ~"QQQgggc,_.,dObc,opooO  `"~~";.   __,7,
qp         t\io,_           `~"TOOggQV""""        _,dg,_ =PIQHib.
`qp        `Q["tQQQo,_                          ,pl{QOP"'   7AFR`
  `         `tb  '""tQQQg,_             p" "b   `       .;-.`Vl'
             "Yb      `"tQOOo,__    _,edb    ` .__   /`/'|  |b;=;.__
                           `"tQQQOOOOP""`"\QV;qQObob"`-._`\_~~-._
                                """"    ._        /   | |oP"\_   ~\ ~\_~\
                                        `~"\ic,qggddOOP"|  |  ~\   `\~-._
                                          ,qP`"""|"   | `\ `;   `\   `\
                               _        _,p"     |    |   `\`;    |    |
      Blood Cat                "boo,._dP"       `\_  `\    `\|   `\   ;
                                 `"7tY~'            `\  `\    `|_   |
                                                      `~\  |
Maptnh@S-H4CK13                 https://github.com/MartinxMax'''

def main():
    print(LOGO)
    parser = argparse.ArgumentParser(description='Blood Cat - RTSP Camera Weak Credential Scanner')
    parser.add_argument('--country', default='', type=str, help='Country')
    parser.add_argument('--city', default='', type=str, help='City')
    parser.add_argument('--region', default='', type=str, help='Area')
    parser.add_argument('--key',  default='', type=str, help='Fofa API key')
    parser.add_argument('--ip', default='', type=str, help='IP or IP:PORT (if no port, will scan common RTSP ports)')
    parser.add_argument('--full-scan', action='store_true', help='Scan all ports first, then check for RTSP (slower but more thorough)')
    parser.add_argument('--port-range', default='', type=str, help='Port range for full scan (e.g., "1-10000" or "1-65535"), default: 1-10000')
    parser.add_argument('--threads', default=50, type=int, help='Number of parallel threads for brute forcing (default: 50, increase for faster scanning)')
    args = parser.parse_args()
    cam = Execute_Cam()
    if not args.ip:
        fofa = Fofa()
        info = fofa.query(
            key=args.key,
            city=args.city,
            country=args.country,
            region=args.region
        )
        if info:
            print("[+] Starting information retrieval")
            for i in info:
                ip = i.split(':')[0]
                port = int(i.split(':')[-1])
                cam.run(ip, port)
    else:
        # Check if port is specified
        if ':' in args.ip:
            ip = args.ip.split(':')[0]
            port = int(args.ip.split(':')[-1])
            cam.run(ip, port, max_workers=args.threads)
        else:
            # Only IP provided, scan for ports
            port_range = None
            if args.port_range:
                try:
                    start, end = args.port_range.split('-')
                    port_range = (int(start), int(end))
                    print(f"[*] Using custom port range: {start}-{end}")
                except:
                    print("[!] Invalid port range format. Use format: 1-10000")
                    return
            
            cam.run(args.ip, None, full_scan=args.full_scan, port_range=port_range, max_workers=args.threads)


if __name__ == '__main__':
    main() 