#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

import datetime

class LogCat:
    RESET = '\033[0m'       
    BLUE = '\033[34m'       
    YELLOW = '\033[33m'     
    PURPLE = '\033[35m'   
    RED = '\033[31m'       
    GREEN = '\033[102m'      
    CYAN = '\033[36m'      
    BOLD = '\033[1m'       

    
    def _get_english_datetime(self):
        now = datetime.datetime.now()
        return now.strftime("%H:%M:%S")

    def _highlight(self, data: str, keyword: str):
        if keyword and keyword in data:
            return data.replace(keyword, f"{self.RED}{keyword}{self.RESET}")
        return data

    def info(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.BLUE}[{datetime_str}] [INFO]{self.RESET} {colored_data}")

    def warning(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.YELLOW}[{datetime_str}] [WARNING]{self.RESET} {colored_data}") 

    def system(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.BOLD}{self.PURPLE}[{datetime_str}] [SYSTEM]{self.RESET} {colored_data}")

    def error(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.BOLD}{self.RED}[{datetime_str}] [ERROR]{self.RESET} {colored_data}")

    def success(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.GREEN}[{datetime_str}] [SUCCESS]{self.RESET} {colored_data}")

    def debug(self, data: str, high_light: str = None):
        datetime_str = self._get_english_datetime()
        colored_data = self._highlight(data, high_light)
        print(f"{self.CYAN}[{datetime_str}] [DEBUG]{self.RESET} {colored_data}")
