#!/bin/bash
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝
import os
import sys
import json
import re
import subprocess
from lib.camlib import * 
from lib.log_cat import * 
log = LogCat()
cam = CamLib()
 
from PyQt5.QtCore import (
    Qt,
    QUrl,
    QTimer,
    QObject,
    pyqtSlot,
    QPropertyAnimation,
    QEasingCurve,
    QSequentialAnimationGroup
)
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QGraphicsOpacityEffect
)
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWebChannel import QWebChannel


HTML = r'''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>BloodCat Map @ S-H4CK13</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
html, body, #map {
    height: 100%;
    margin: 0;
    padding: 0;
    background-color: #000;  
    cursor: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="24" width="30"><text x="0" y="20" font-size="20" fill="lime" font-weight="bold">[ ]</text></svg>') 12 12, auto;
}

.ip-tooltip{
    background: rgba(0,0,0,0.78);
    color: #fff;
    font-size: 12px;
    padding: 6px 10px;
    border-radius: 6px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.35);
    pointer-events: none;
    white-space: nowrap;
    font-family: "Segoe UI", Arial, sans-serif;
}

.leaflet-marker-icon:hover {
    cursor: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="24" width="50"><text x="0" y="20" font-size="20" fill="lime" font-weight="bold">[+]</text></svg>') 12 12, pointer;
}

#searchBox {
    position: absolute;
    top: 10px;
    right: 10px;
    z-index: 9999;
    background: rgba(0,0,0,0.7);
    color: #fff;
    padding: 6px;
    border-radius: 6px;
    width: 220px;
    font-family: "Segoe UI", Arial, sans-serif;
}
#searchInput {
    width: 100%;
    padding: 4px 6px;
    border-radius: 4px;
    border: none;
    outline: none;
    background: #222;
    color: #0f0;
}
#searchResults {
    max-height: 150px;
    overflow-y: auto;
    margin-top: 4px;
    font-size: 12px;
}
.searchItem {
    padding: 4px;
    cursor: pointer;
}
.searchItem:hover {
    background: rgba(0,255,0,0.3);
}
</style>
</head>
<body>
<div id="map"></div>
<div id="searchBox">
    <input type="text" id="searchInput" placeholder="Search IP / ASN / Network"/>
    <div id="searchResults"></div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="qrc:///qtwebchannel/qwebchannel.js"></script>
<script>
const map = L.map('map').setView([20,0],2);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
    subdomains: 'abcd',
    maxZoom: 19
}).addTo(map);

const icon = L.icon({iconUrl:'./location/main.png', iconSize:[32,32], iconAnchor:[16,32]});
const markers = {};   // ip -> marker
const rtspMap = {};   // ip -> rtsp
let dataStore = {};   // ip -> data_obj

let bridge = null;
new QWebChannel(qt.webChannelTransport, function(channel){
    bridge = channel.objects.bridge;
    console.log('WebChannel initialized, bridge=', bridge);
});

function updateMarkers(data_obj){
    dataStore = data_obj; 
    for (let ip in markers){
        if (!(ip in data_obj)){
            map.removeLayer(markers[ip]);
            delete markers[ip];
            delete rtspMap[ip];
        }
    }

    for (let ip in data_obj){
        const item = data_obj[ip];
        const parts = ('' + item.lalo).split(',').map(x=>parseFloat(x));
        if (parts.length < 2 || isNaN(parts[0]) || isNaN(parts[1])) continue;
        const coords = [parts[0], parts[1]];
        rtspMap[ip] = item.rtsp;

        if (markers[ip]){
            markers[ip].setLatLng(coords);
        } else {
            const m = L.marker(coords, {icon: icon}).addTo(map);
            m.bindTooltip("watch...", {permanent:false, direction:'top'});

            const infoHtml = `${ip}<br>${item.sys_org}<br>ASN: ${item.asn}<br>${item.network}`;
            m.on('mouseover', function(e){
                m.bindTooltip(infoHtml, {permanent:false, direction:'top', offset:[0,-35], className:'ip-tooltip'}).openTooltip();
            });
            m.on('mouseout', function(e){
                m.closeTooltip();
            });

            m.on('click', function(){
                if (bridge && bridge.playRTSP){
                    try{ bridge.playRTSP(item.rtsp); }
                    catch(e){ console.error('bridge.playRTSP error', e); }
                } else { console.warn('bridge not ready'); }
            });

            m.bindPopup(infoHtml);
            markers[ip] = m;
        }
    }
}

const input = document.getElementById('searchInput');
const resultsDiv = document.getElementById('searchResults');

input.addEventListener('input', function(){
    const query = this.value.toLowerCase();
    resultsDiv.innerHTML = '';
    if (!query) return;

    for (let ip in dataStore){
        const item = dataStore[ip];
        const text = `${ip} ${item.asn} ${item.network}`.toLowerCase();
        if (text.includes(query)){
            const div = document.createElement('div');
            div.className = 'searchItem';
            div.textContent = `${ip} | ${item.asn} | ${item.network}`;
            div.onclick = function(){
                const parts = ('' + item.lalo).split(',').map(x=>parseFloat(x));
                if (parts.length >= 2){
                    map.setView([parts[0], parts[1]], 10); 
                }
                resultsDiv.innerHTML = '';
                input.value = '';
            };
            resultsDiv.appendChild(div);
        }
    }
});
</script>
</body>
</html>

'''

LOGO = "\033[38;5;208m"+r'''
                                               .--.
                                               `.  \
                                                 \  \
                                                  .  \
                                                  :   .
                                                  |    .
                                                  |    :
                                                  |    |
  ..._  ___                                       |    |
 `."".`---'""--..___                              |    |
 ,-\  \             ""-...__         _____________/    |
 / ` " '                    `""""""""                  .
 \                                                      L
 (>                                                      \
/                                                         \
\_    ___..---.                                            L
  `--'         '.                                           \
                 .                                           \_
                _/`.                                           `.._
             .'     -.                                             `.
            /     __.-Y     /''''''-...___,...--------.._            |
           /   _."    |    /                ' .      \   '---..._    |
          /   /      /    /                _,. '    ,/           |   |
          \_,'     _.'   /              /''     _,-'            _|   |
                  '     /               `-----''               /     |
                  `...-'                                       `...
[Maptnh@S-H4CK13]      [Blood Cat V2.2 Map]    [https://github.com/MartinxMax]'''+"\033[0m"

class Bridge(QObject):
    @pyqtSlot(str)
    def playRTSP(self, url):
        ffplay_bin = r'.\lib\ffplay.exe' if sys.platform.startswith('win') else 'ffplay'
        match = re.search(r'@([\d\.]+):', url)
        if match:
            ip = match.group(1)
        else:
            ip = 'N/A'
        try:
            subprocess.Popen(
                [ffplay_bin, '-rtsp_transport', 'tcp', '-x', '420', '-y', '340', url,'-window_title',ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False
            )
            print(f"[+] Playing: {url}")
        except FileNotFoundError:
            print("\033[31m[!] ffplay not found, please install ffmpeg \033[0m")
        except Exception as e:
            print("\033[31m[!] Playback error:", e, "\033[0m")

class MapWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BloodCat Map @ S-H4CK13    [https://github.com/MartinxMax]")
        self.resize(1280, 800)

 
        icon_path = os.path.join(os.path.dirname(__file__), "location","ico.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

 
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)


        self.view = QWebEngineView()
        self.layout.addWidget(self.view)


        self.wait_label = QLabel(self)
        self.wait_label.setAlignment(Qt.AlignCenter)
        self.wait_label.setStyleSheet("background-color: rgba(0,0,0,1);")
        self.wait_label.setAttribute(Qt.WA_TransparentForMouseEvents) 

        wait_path = os.path.join(os.path.dirname(__file__), "location", "wait.png")
        self.wait_pixmap = None
        if os.path.exists(wait_path):
            self.wait_pixmap = QPixmap(wait_path)
            self._update_wait_pixmap()
        else:
            print(f"\033[31m[!] No found background: {wait_path}\033[0m")

        self.wait_label.raise_()
        self.wait_label.show()


        self._setup_wait_animation()

       
        self.html_path = os.path.join(os.path.dirname(__file__), "map_temp.html")
        with open(self.html_path, "w", encoding="utf-8") as f:
            f.write(HTML)

    
        self.channel = QWebChannel()
        self.bridge = Bridge()
        self.channel.registerObject('bridge', self.bridge)
        self.view.page().setWebChannel(self.channel)


        self.last_data = {}
        self.view.loadFinished.connect(self.on_load_finished)
        self.view.load(QUrl.fromLocalFile(os.path.abspath(self.html_path)))

    def _update_wait_pixmap(self):
        if not self.wait_pixmap:
            self.wait_label.setFixedSize(self.size())
            return
        scaled = self.wait_pixmap.scaled(
            self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation
        )
        self.wait_label.setPixmap(scaled)
        self.wait_label.setGeometry(self.rect())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_wait_pixmap()

    def _setup_wait_animation(self):
        from PyQt5.QtCore import QSequentialAnimationGroup, QPropertyAnimation, QEasingCurve

        self._opacity_effect = QGraphicsOpacityEffect(self.wait_label)
        self.wait_label.setGraphicsEffect(self._opacity_effect)
        self._opacity_effect.setOpacity(1.0)

        self.anim_group = QSequentialAnimationGroup()

        anim1 = QPropertyAnimation(self._opacity_effect, b"opacity")
        anim1.setDuration(1500)
        anim1.setStartValue(1.0)
        anim1.setEndValue(0.2)
        anim1.setEasingCurve(QEasingCurve.InOutSine)

        anim2 = QPropertyAnimation(self._opacity_effect, b"opacity")
        anim2.setDuration(1500)
        anim2.setStartValue(0.2)
        anim2.setEndValue(1.0)
        anim2.setEasingCurve(QEasingCurve.InOutSine)

        anim3 = QPropertyAnimation(self._opacity_effect, b"opacity")
        anim3.setDuration(1000)
        anim3.setStartValue(1.0)
        anim3.setEndValue(0.0)
        anim3.setEasingCurve(QEasingCurve.InOutQuad)
        anim3.finished.connect(self.wait_label.hide)

        self.anim_group.addAnimation(anim1)
        self.anim_group.addAnimation(anim2)
        self.anim_group.addAnimation(anim3)
        self.anim_group.start()

    def on_load_finished(self, ok):
        if not ok:
            print("\033[31m[!] BloodCat config file load failed... please check your network...\033[0m")
            return
        self.refresh_data()

    def refresh_data(self):
        self.view.page().runJavaScript("typeof updateMarkers === 'function';", self._js_check_ready)

    def _js_check_ready(self, result):
        if result:
            self._send_data_to_js()

    def _send_data_to_js(self):
        log.info("Fetching encrypted file data from the remote server...")
        data = cam.get_DB_data()
        if not data:
            return
        log.info("Fetch successful...")
        new_data = {}
        for line in data.splitlines():
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                rtsp = obj.get("rtsp", "")
                data = obj.get("data", {})
                lalo = data.get("lalo", "")
                sys_org = data.get("sys_org", "")
                asn = data.get("asn", "")
                network = data.get("network", "")
                m = re.search(r'@([\d\.]+):?', rtsp)
                if m and lalo:
                    ip = m.group(1)
                    new_data[ip] = {
                        "rtsp": rtsp,
                        "lalo": lalo,
                        "sys_org": sys_org,
                        "asn": asn,
                        "network": network
                    }
            except: continue

        if new_data != self.last_data:
            self.last_data = new_data
            try:
                js = "updateMarkers(%s);" % json.dumps(new_data, ensure_ascii=False)
                self.view.page().runJavaScript(js)
            except Exception as e:
                print("\033[31m[!] runJavaScript failed:", e,"\033[0m")


if __name__ == "__main__":
    print(LOGO)
    app = QApplication(sys.argv)
    win = MapWindow()
    win.showMaximized()
    sys.exit(app.exec_())
