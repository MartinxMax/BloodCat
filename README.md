# Blood-Cat

A powerful tool for discovering and brute-forcing RTSP camera credentials, with support for automatic port detection, parallel scanning, and comprehensive password lists.

---

## Features

- **Automatic Port Detection**: Scans common RTSP ports or performs full port scans
- **Parallel Brute Forcing**: Multi-threaded credential testing for maximum speed
- **Comprehensive Password Lists**: 135+ common passwords and 28+ usernames
- **Device Detection**: Automatically detects camera brands (Hikvision, Dahua, Axis, etc.) and uses appropriate paths
- **Multiple Scanning Modes**: Quick scan (common ports) or full port scan
- **Customizable**: Configurable thread count and port ranges

---

## Install Dependencies

```bash
$ sudo apt update && sudo apt install ffmpeg
$ pip install -r requirements.txt
```

---

## Usage

```bash
$ python3 bloodcat.py -h
```

### Basic Usage

**Brute force a specific camera IP with port:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247:8554"
```

**Brute force with automatic port detection (scans common RTSP ports):**
```bash
$ python3 bloodcat.py --ip "192.168.0.247"
```

**Full port scan (scans all ports 1-10000, then checks for RTSP):**
```bash
$ python3 bloodcat.py --ip "192.168.0.247" --full-scan
```

**Full port scan with custom port range:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247" --full-scan --port-range "1-65535"
```

**Faster brute forcing with more threads:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247:8554" --threads 100
```

**Maximum speed (200 threads):**
```bash
$ python3 bloodcat.py --ip "192.168.0.247:8554" --threads 200
```

### Advanced Options

**Brute force camera IPs in a specific country/region (via FoFa):**
```bash
$ python3 bloodcat.py --country CN --region HK --key <FOFA-API-KEY>
```

### Command-Line Arguments

- `--ip`: IP address or IP:PORT format. If no port specified, will scan for RTSP ports
- `--full-scan`: Enable full port scan mode (scans all ports first, then checks for RTSP)
- `--port-range`: Custom port range for full scan (e.g., "1-10000" or "1-65535"), default: 1-10000
- `--threads`: Number of parallel threads for brute forcing (default: 50, increase for faster scanning)
- `--country`: Country code for FoFa search
- `--region`: Region for FoFa search
- `--city`: City for FoFa search
- `--key`: FoFa API key

---

## Scanning Modes

### Quick Scan (Default)
When you provide only an IP address, the tool will:
1. Scan 13 common RTSP ports (554, 8554, 5544, etc.)
2. Check which ports have RTSP service
3. Automatically brute force each found port

**Example:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247"
```

### Full Port Scan
When using `--full-scan`, the tool will:
1. **Phase 1**: Scan all ports in range (default: 1-10000) to find open ports
2. **Phase 2**: Check which open ports are RTSP services
3. **Phase 3**: Automatically brute force each RTSP port found

**Example:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247" --full-scan --port-range "1-65535"
```

---

## Performance

The tool uses parallel threading to maximize brute force speed:

- **Default (50 threads)**: ~50-100 attempts/second
- **Fast (100 threads)**: ~100-200 attempts/second  
- **Maximum (200 threads)**: ~200-400 attempts/second

Actual speed depends on:
- Network latency to the camera
- Camera response time
- Your network bandwidth

---

## Password Lists

The tool includes comprehensive password lists:

- **135+ Common Passwords**: Including most common weak passwords, camera defaults, numeric patterns, and camera-related words
- **28+ Usernames**: Including admin, root, user, guest, administrator, and camera-specific usernames

The tool tries all combinations of usernames × passwords × RTSP paths automatically.

---

## File Path

All discovered results will be saved to:

```
./data/ipcam.info
```

Each line contains a valid RTSP URL in the format:
```
rtsp://username:password@ip:port/path
```

---

## Launch Viewer

```bash
$ ./play.sh
```

This will launch `ffplay` for each discovered RTSP stream.

---

## Common RTSP Ports Scanned

When using quick scan mode, the tool checks these common RTSP ports:
- 554 (default RTSP)
- 8554 (common alternative)
- 5544, 5554, 1935, 8080, 8888, 1554, 10554
- 8555, 8556, 8557, 8558

---

## Device Support

The tool automatically detects and uses appropriate paths for:
- Hikvision
- Dahua
- Uniview
- Axis
- Sony
- Vivotek
- TVT
- Reolink
- Milesight

For unknown devices, it uses a comprehensive default path list.

---

## Examples

**Quick scan with default settings:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247"
```

**Full port scan with maximum speed:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247" --full-scan --threads 200
```

**Specific port with custom thread count:**
```bash
$ python3 bloodcat.py --ip "192.168.0.247:8554" --threads 100
```

---

## Notes

- The tool will automatically stop when valid credentials are found
- Progress bars show real-time scanning and brute force progress
- All discovered RTSP URLs are automatically saved to `./data/ipcam.info`
- For best performance on local networks, use higher thread counts (100-200)
- For remote targets, use default or lower thread counts to avoid overwhelming the connection
