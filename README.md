# ESP32 Pwnagotchi v18

> **⚠️ For authorised security testing on your own networks only.**
> Unauthorised use against networks you do not own or have explicit written permission to test is **illegal** in most jurisdictions.

An ESP32-based WiFi security research tool inspired by the original [Pwnagotchi](https://pwnagotchi.ai/) project.
Runs entirely on a single ESP32 with an SSD1306 OLED and an analogue joystick — no Raspberry Pi, no Python, no battery management IC required.

---

## ✨ Features

| # | Module | Description |
|---|--------|-------------|
| 1 | **SCAN** | Active 2.4 GHz WiFi scan, sorted by RSSI |
| 2 | **DEAUTH** | Rogue-AP spoof + raw 802.11 frame injection, optional CH-hopping |
| 3 | **DEAUTH ALL** | Broadcast-deauth every discovered AP simultaneously |
| 4 | **EVIL TWIN** | Fake AP + captive portal (3 themes: WLAN / Google / Router) capturing username + password |
| 5 | **KARMA ATK** | Listens for probe requests and spawns a matching fake AP automatically |
| 6 | **HANDSHAKE** | Passive WPA2 4-way handshake capture saved as `.pcap` |
| 7 | **PWNAGOTCHI** | Fully autonomous AI-style pwning agent (see below) |
| 8 | **BEACON** | SSID spoofer — floods the air with 15 rotating SSIDs |
| 9 | **PROBE SNIFF** | Captures probe requests: shows which SSIDs nearby devices are searching for |
| 10 | **CH SCAN** | Per-channel traffic heatmap (bar graph, channels 1–13) |
| 11 | **SIG TRACK** | Live RSSI graph to physically locate an AP |
| 12 | **WEBSERVER** | Download captured credentials and handshakes via browser |
| 13 | **STORAGE** | View and wipe LittleFS (credentials / handshakes) |
| 14 | **PKT MON** | Live packets-per-second waveform |

---

## 🤖 Pwnagotchi Mode

The autonomous agent scans, picks targets, and attacks without any human input.

### How it works

```
Boot → IDLE → SCAN → pick best target → TARGET (3 s pause)
     → ATTACK (Evil Twin + Deauth burst)
         ├─ Credential captured → PWNED (celebrate) → next target
         └─ Timeout (90 s)      → blacklist AP       → next target
                                    └─ All candidates tried → EXHAUSTED → rest → RESCAN
```

### Smart failover

1. Scans all 2.4 GHz APs, sorts by RSSI (strongest first).
2. Prefers **WPA2 > WPA/2 > WPA** targets with a visible SSID.
3. Launches **Evil Twin captive portal** + continuous **deauth burst** on the target.
4. If no credential is entered within **90 seconds**, the AP is **blacklisted** for this epoch.
5. Automatically moves on to the **next best non-blacklisted AP**.
6. After trying up to **5 APs per epoch** (configurable), enters a rest period then rescans fresh.
7. **Persistent stats** — total pwned count and epoch number survive reboots (stored in LittleFS).

### OLED layout

```
ep:3 ch:7 aps:12 up:43s     ← stats header
─────────────────────────
        (*O*)                ← ASCII face (size 2, centred)
─────────────────────────
pwn:4 hs:2                  ← counters
A target! >:D               ← mood status text
>>HomeWifi                  ← current target SSID
```

### Faces & moods

| Face | Mood |
|------|------|
| `(0_0)` | Awake / boot |
| `(-_-)` | Bored |
| `( ^_^)` / `(^_^ )` | Scanning (eyes shift channels) |
| `(*O*)` | Target found |
| `(>_<)*` | Deauthing |
| `(>_<)` | Waiting for password |
| `(>:D)` | PWNED! |
| `(;_;)` | Sad / no targets |
| `(^o^)` | Happy (after capture) |

Random blink animation triggers every 4–8 seconds.

---

## 🛒 Hardware

| Component | Notes |
|-----------|-------|
| **ESP32 DevKit v1** | Any 38-pin variant works |
| **SSD1306 OLED 128×64** | I²C; connect SDA→GPIO21, SCL→GPIO22 |
| **Analogue joystick** | VRX→GPIO34, VRY→GPIO35, SW→GPIO33 |
| LiPo battery + TP4056 | Optional, for portable use |

### Wiring

```
OLED SDA  → GPIO 21
OLED SCL  → GPIO 22
OLED VCC  → 3.3 V
OLED GND  → GND

Joystick VRX → GPIO 34
Joystick VRY → GPIO 35
Joystick SW  → GPIO 33 (+ 10 kΩ pull-up or use INPUT_PULLUP)
Joystick VCC → 3.3 V
Joystick GND → GND
```

---

## 🔧 Build & Flash

### Arduino IDE

1. Install **Arduino IDE 2.x** and add the ESP32 board package:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`

2. Install libraries via Library Manager:
   - `Adafruit SSD1306`
   - `Adafruit GFX Library`

3. Open `esp32_pwnagotchi.ino`.
   Make sure **all three files** are in the same sketch folder:
   ```
   esp32_pwnagotchi/
   ├── esp32_pwnagotchi.ino
   ├── build_opt.h          ← linker flag for raw frame injection
   └── deauth_patch.c       ← frame sanity-check bypass
   ```

4. Board settings:
   ```
   Board            : ESP32 Dev Module
   Partition Scheme : Default 4MB with spiffs (1.2MB APP / 1.5MB SPIFFS)
   Upload Speed     : 921600
   ```

5. Click **Upload**.

### PlatformIO

```ini
[env:esp32dev]
platform  = espressif32
board     = esp32dev
framework = arduino
lib_deps  =
    adafruit/Adafruit SSD1306
    adafruit/Adafruit GFX Library
board_build.partitions = default.csv
build_flags =
    -Wl,--wrap=ieee80211_raw_frame_sanity_check
```

---

## 🕹️ Controls

| Action | Effect |
|--------|--------|
| Joystick UP / DOWN | Scroll menu |
| Joystick LEFT / RIGHT | Scroll AP list |
| Joystick UP (in DEAUTH SELECT) | Toggle HOP / FIX mode |
| **Click** | Select / confirm |
| **Click** (during any attack) | Stop and return to menu |
| **Left** (during any attack) | Stop and return to menu |

---

## 🌐 Webserver

After capturing credentials or handshakes, select **WEBSERVER** from the menu.

Connect your phone or laptop to WiFi:
- **SSID:** `pwnagotchi-data`
- **Password:** `pwnagotchi`

Then open: **http://192.168.4.1:8080**

The page lists all captured credentials and handshake `.pcap` files available for download.
The `.pcap` files can be opened with **Wireshark** or cracked with **hashcat** / **aircrack-ng**.

---

## 🔑 Cracking handshakes

```bash
# Convert pcap to hashcat format
hcxpcapngtool -o hash.hc22000 hs_YourSSID.pcap

# Crack with wordlist
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Or with aircrack-ng
aircrack-ng hs_YourSSID.pcap -w /usr/share/wordlists/rockyou.txt
```

---

## ⚙️ Configuration

All tuning constants are at the top of `esp32_pwnagotchi.ino`:

```cpp
// ── PWNAGOTCHI TUNING ────────────────────────────────────────
#define PW_ATTACK_TIMEOUT_S   90   // seconds before blacklisting a target
#define PW_RESCAN_INTERVAL_S  15   // seconds to rest between scan epochs
#define PW_TARGET_PAUSE_S      3   // seconds to show FOUND face before attacking
#define PW_CELEBRATE_S         5   // seconds to celebrate after PWNED
#define PW_MAX_TRIES_PER_EPOCH 5   // max APs to try before resting
```

---

## 📂 File Structure

```
esp32_pwnagotchi/
├── esp32_pwnagotchi.ino   Main sketch (~2000 lines)
├── build_opt.h            Linker flag for raw frame injection
├── deauth_patch.c         IEEE 802.11 frame sanity bypass
└── README.md              This file
```

LittleFS storage layout (on-device):
```
/creds.txt        Captured Evil Twin credentials (append-only)
/hs_<SSID>.pcap   WPA2 handshake captures
/pw_stats.bin     Pwnagotchi persistent stats (6 bytes)
```

---

## 📝 Serial Monitor

Connect at **115200 baud** for debug output. During runtime, type:

| Key | Output |
|-----|--------|
| `s` | LittleFS storage stats |
| `l` | List all files on LittleFS |
| `p` | Pwnagotchi state (pwned count, epoch, phase) |

---

## 🔒 Legal Notice

This tool is intended **exclusively** for:
- Security research on **networks you own**
- Penetration testing with **explicit written authorisation**
- Educational purposes in a **controlled lab environment**

Deploying this against public or third-party networks without permission is a criminal offence in most countries (e.g. CFAA in the USA, Computer Misuse Act in the UK, §202a StGB in Germany).

The authors accept **no liability** for misuse.

---

## 🙏 Acknowledgements

- [Pwnagotchi](https://pwnagotchi.ai/) — the original project and inspiration
- [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32)
- [Adafruit GFX / SSD1306](https://github.com/adafruit/Adafruit_SSD1306)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
