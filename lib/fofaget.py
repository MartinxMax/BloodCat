#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

import requests
import base64
import json
from lib.log_cat import LogCat
log = LogCat()

class Fofa():
    def query(self,country,key,region,city):
        log.info(f"Fetching network cameras in [{country} {region} {city}]")
        query_ = f'country="{country}"&& (region="{region}"||city="{city}")&& banner="RTSP/1.0" && protocol="rtsp" && port="554"'
        qbase64 = base64.b64encode(query_.encode()).decode()  
        url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={qbase64}"
        data = requests.get(url)
        datas = json.loads(data.text)
        if datas.get('results'):
            ip_ports = [item[0] for item in datas['results']]
            log.success("Got data from Fofa...")
            return ip_ports
        else:
            log.error("Query error....")
            return