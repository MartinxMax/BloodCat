cve_2017_7921_config = {
    "CVE": "CVE-2017-7921",
    "dev": "Hikvision",
    "descript": "Hikvision auth bypass",
    "module": "modules.CVE_2017_7921",
    "parameter": {
        "ips": {
            "var": '',
            "descript": "Hosts file (<IP>:<Port>)"
        },
        "threads": {
            "var": 10,
            "descript": "Thread count"
        },
        "output_type": {
            "var": "csv",
            "descript": "json / csv"
        },
        "output_path": {
            "var": "./result.csv",
            "descript": "Output file"
        }
    }
}
cve_2025_7503_config = {
    "CVE": "CVE-2025-7503",
    "dev": "Liandian",  
    "descript": "Liandian IP Camera Telnet Hardcoded Credentials & Plaintext WiFi Credentials Leak",
    "module": "modules.CVE_2025_7503",  
    "parameter": {
        "ip": {
            "var": '',
            "descript": "ip address"
        },
        "port": {
            "var": 23,
            "descript": "telnet port"
        },
        "timeout": {
            "var": 10,
            "descript": "timeout"
        },
 
    }
}
CVE_2016_20016_config = {
    "CVE": "CVE-2016-20016",
    "dev": "JAWS-DVR",  
    "descript": "MVPower and certain DVR devices identified by the JAWS/1.0 banner are affected by an unauthenticated remote command execution (RCE) vulnerability",
    "module": "modules.CVE_2016_20016",  
    "parameter": {
        "url": {
            "var": '',
            "descript": "url"
        }
    }
}
CVE_2016_5674_config = {
    "CVE": "CVE-2016-5674",
    "dev": "NUUO-NVR",  
    "descript": "Remote attackers execute arbitrary PHP code via log parameter",
    "module": "modules.CVE_2016_5674",  
    "parameter": {
        "url": {
            "var": '',
            "descript": "url"
        }
    }
}

all_modules = [
    cve_2017_7921_config,
    cve_2025_7503_config,
    CVE_2016_20016_config,
    CVE_2016_5674_config
]
