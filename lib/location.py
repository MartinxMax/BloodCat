#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

from geoip2 import database

class Location():
    def __init__(self):
        self.city_reader = database.Reader("./lib/city.mmdb")
        self.asn_reader = database.Reader("./lib/asn.mmdb")
        
    def get(self, ip: str):
        city_response = self.city_reader.city(ip)
        asn_response = self.asn_reader.asn(ip)
        data = {
            'country': city_response.country.name,
            'city': city_response.city.name,
            'lalo': f"{city_response.location.latitude},{city_response.location.longitude}",
            'asn': asn_response.autonomous_system_number,
            'sys_org': asn_response.autonomous_system_organization,
            'network': str(asn_response.network)
        }
        return data
    
    def close(self):
        self.city_reader.close()
        self.asn_reader.close()

    def __del__(self):
        self.close()