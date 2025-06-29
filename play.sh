#!/bin/bash
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

 
if ! command -v ffplay &> /dev/null
then
    echo "ffplay is not installed."
    echo "You can install it by running:"
    echo "  sudo apt update && sudo apt install ffmpeg"
    exit 1
fi

 
FILE="./data/ipcam.info"
if [ ! -f "$FILE" ]; then
    echo "File $FILE not found!"
    exit 1
fi

 
while IFS= read -r line
do
 
    if [[ -z "$line" || ! "$line" =~ ^rtsp:// ]]; then
        continue
    fi

    echo "Playing stream: $line"
    ffplay -rtsp_transport tcp -x 420 -y 340 "$line" &
    sleep 1
done < "$FILE"

wait
