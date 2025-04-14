/*
 * USER VARIABLES
 */
 
// Put your SoftAP config here
String AP_SSID = "CAPPER";
String AP_Password = "12345678";
String AP_Channel = "1";





/*
 * SYSTEM VARIABLES, MODIFY AS YOU NEED, OTHERWISE LEAVE IT
 */
 
int status = WL_IDLE_STATUS;
int ssid_status = 0;                      // Set SSID status, 1 hidden, 0 not hidden
IPAddress forwardedIp(192, 168, 1, 1);    // Static IP for AP (changed to 192.168.4.1)
WiFiServer webServer(80);                 // Initialize the server on port 80

const int RSSI_MAX = -50; // define maximum strength of signal in dBm
const int RSSI_MIN = -100; // define minimum strength of signal in dBm
void performScan();
typedef struct
{
  String ssid;
  bool hidden;
  uint8_t ch;
  uint8_t bssid[6];
  uint8_t rs;
  uint8_t enc;
  String band;
  uint8_t pkts;
  uint8_t sta_count;

}  _Network;

_Network _networks[32];
_Network _selectedNetwork;

void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param);

char ap_ssid[33] = "";  
char ap_pass[33] = "";                
char ap_channel[4] = "";                   

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);

    if (i < size - 1) str += DOUBLEPOINT;
  }
  return str;
}

#define SCAN_INTERVAL 3000
// RSSI RANGE
#define RSSI_CEILING -40
#define RSSI_FLOOR -100

static uint8_t _networkCount;
static char _networkSsid[WL_NETWORKS_LIST_MAXNUM][WL_SSID_MAX_LENGTH];
static int32_t _networkRssi[WL_NETWORKS_LIST_MAXNUM];
static uint32_t _networkEncr[WL_NETWORKS_LIST_MAXNUM];
static uint8_t _networkChannel[WL_NETWORKS_LIST_MAXNUM];
static uint8_t _networkBand[WL_NETWORKS_LIST_MAXNUM];
static String _networkBandStr[WL_NETWORKS_LIST_MAXNUM];
static char _networkMac[WL_NETWORKS_LIST_MAXNUM][18];
static int _selectedNetworkIdx[32] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};


void printEncryptionTypeEx(uint32_t thisType) {
    switch (thisType) {
        case RTW_SECURITY_OPEN:
            Serial.print(F("Open"));
            break;
        case RTW_SECURITY_WEP_PSK:
            Serial.print(F("WEP"));
            break;
        case RTW_SECURITY_WPA_TKIP_PSK:
            Serial.print(F("WPA TKIP"));
            break;
        case RTW_SECURITY_WPA_AES_PSK:
            Serial.print(F("WPA AES"));
            break;
        case RTW_SECURITY_WPA2_AES_PSK:
            Serial.print(F("WPA2 AES"));
            break;
        case RTW_SECURITY_WPA2_TKIP_PSK:
            Serial.print(F("WPA2 TKIP"));
            break;
        case RTW_SECURITY_WPA2_MIXED_PSK:
            Serial.print(F("WPA2 Mixed"));
            break;
        case RTW_SECURITY_WPA_WPA2_MIXED_PSK:
            Serial.print(F("WPA/WPA2 AES"));
            break;
        case RTW_SECURITY_WPA3_AES_PSK:
            Serial.print(F("WPA3 AES"));
            break;
        case RTW_SECURITY_WPA2_WPA3_MIXED:
            Serial.print(F("WPA2/WPA3"));
    }
}

int dBmtoPercentage(int dBm)
{
  int quality;
    if(dBm <= RSSI_MIN)
    {
        quality = 0;
    }
    else if(dBm >= RSSI_MAX)
    {  
        quality = 100;
    }
    else
    {
        quality = 2 * (dBm + 100);
   }

     return quality;
}

void storeNetworkDetails(rtw_scan_result_t record) {
  strcpy(_networkSsid[_networkCount], (char *)record.SSID.val);
  _networkRssi[_networkCount] = record.signal_strength;
  _networkEncr[_networkCount] = record.security;
  _networkChannel[_networkCount] = record.channel;
  _networkBand[_networkCount] = record.band;

  sprintf(_networkMac[_networkCount], "%02X:%02X:%02X:%02X:%02X:%02X",
    record.BSSID.octet[0], record.BSSID.octet[1], record.BSSID.octet[2],
    record.BSSID.octet[3], record.BSSID.octet[4], record.BSSID.octet[5]);

  // Print details for debugging
  Serial.print(String(_networkCount) + ") ");
  Serial.print(_networkSsid[_networkCount]);
  Serial.print(F("\tSignal: "));
  Serial.print(_networkRssi[_networkCount]);
  Serial.print(F(" dBm"));
  Serial.print(F("\tEncryptionRaw: "));
  printEncryptionTypeEx(_networkEncr[_networkCount]);
  Serial.print(F("\tBand: "));
  Serial.print(_networkChannel[_networkCount] < 14 ? "2.4 Ghz" : "5 Ghz");
  Serial.print(F("\tChannel: "));
  Serial.print(_networkChannel[_networkCount]);
  Serial.print(F("\tMac: "));
  Serial.print(_networkMac[_networkCount]);
  Serial.println("");

  if (record.channel < 14) {
    //Serial.print("2.4 Ghz");
    _networkBandStr[_networkCount] = F("2.4 Ghz");
  } else {
    //Serial.print("5 Ghz");
    _networkBandStr[_networkCount] = F("5 Ghz");
  }

  _networks[_networkCount].ssid = _networkSsid[_networkCount];

  if (_networks[_networkCount].ssid == "") {_networks[_networkCount].ssid = "[HIDDEN SSID]";}
  
  _networks[_networkCount].bssid[0] = record.BSSID.octet[0];
  _networks[_networkCount].bssid[1] = record.BSSID.octet[1];
  _networks[_networkCount].bssid[2] = record.BSSID.octet[2];
  _networks[_networkCount].bssid[3] = record.BSSID.octet[3];
  _networks[_networkCount].bssid[4] = record.BSSID.octet[4];
  _networks[_networkCount].bssid[5] = record.BSSID.octet[5];
  _networks[_networkCount].ch = _networkChannel[_networkCount];
  _networks[_networkCount].rs = dBmtoPercentage(_networkRssi[_networkCount]);
  _networks[_networkCount].band = _networkBandStr[_networkCount];

  _networkCount++;
}

static rtw_result_t wifidrv_scan_result_handler(rtw_scan_handler_result_t *malloced_scan_result) {
  rtw_scan_result_t *record;
  static rtw_scan_result_t temp_ap_list[WL_NETWORKS_LIST_MAXNUM];
  static int temp_network_count = 0;

  // Step 1: Store the AP details in a temporary list
  if (malloced_scan_result->scan_complete != RTW_TRUE) {
    record = &malloced_scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0; /* Ensure the SSID is null terminated */

    // Store the current AP record in a temporary list
    if (temp_network_count < WL_NETWORKS_LIST_MAXNUM) {
      memcpy(&temp_ap_list[temp_network_count], record, sizeof(rtw_scan_result_t));
      temp_network_count++;
    }
  } else { // Step 2: Process the list once the scan is complete

    // Step 3: First loop through and store all 5GHz networks
    for (int i = 0; i < temp_network_count; i++) {
      if (temp_ap_list[i].channel >= 36 && temp_ap_list[i].channel <= 165) {
        // Store 5GHz network details
        if (_networkCount < WL_NETWORKS_LIST_MAXNUM) {
          storeNetworkDetails(temp_ap_list[i]);
        }
      }
    }

    // Step 4: Now loop through and store all 2.4GHz networks
    for (int i = 0; i < temp_network_count; i++) {
      if (temp_ap_list[i].channel < 14) {
        // Store 2.4GHz network details
        if (_networkCount < WL_NETWORKS_LIST_MAXNUM) {
          storeNetworkDetails(temp_ap_list[i]);
        }
      }
    }

    // Reset the temporary list and network count after processing
    temp_network_count = 0;
  }

  return RTW_SUCCESS;
}

// Channel legend mapping
static uint16_t channel_legend[] = {
    1, 2, 3, 4, 5, 6, 7,      //  1,  2,  3,  4,  5,  6,  7,
    8, 9, 10, 11, 12, 13, 14, //  8,  9, 10, 11, 12, 13, 14,
    32, 0, 0, 0, 40, 0, 0,    // 32, 34, 36, 38, 40, 42, 44,
    0, 48, 0, 0, 0, 56, 0,    // 46, 48, 50, 52, 54, 56, 58,
    0, 0, 64, 0, 0, 0,        // 60, 62, 64, 68,N/A, 96,
    100, 0, 0, 0, 108, 0, 0,  //100,102,104,106,108,110,112,
    0, 116, 0, 0, 0, 124, 0,  //114,116,118,120,122,124,126,
    0, 0, 132, 0, 0, 0, 140,  //128,N/A,132,134,136,138,140,
    0, 0, 0, 149, 0, 0, 0,    //142,144,N/A,149,151,153,155,
    157, 0, 0, 0, 165, 0, 0,  //157,159,161,163,165,167,169,
    0, 173};                  //171,173

static uint16_t channelIdx(int channel)
{
  if (channel <= 14) // 2.4 GHz, channel 1-14
  {
    return channel - 1;
  }
  if (channel <= 64) // 5 GHz, channel 32 - 64
  {
    return 14 + ((channel - 32) / 2);
  }
  if (channel == 68)
  {
    return 31;
  }
  if (channel == 96)
  {
    return 33;
  }
  if (channel <= 144) // channel 98 - 144
  {
    return 34 + ((channel - 100) / 2);
  }
  // channel 149 - 177
  return 58 + ((channel - 149) / 2);
}





static int8_t scanNetworks()
{
  uint8_t attempts = 10;

  _networkCount = 0;
  if (wifi_scan_networks_mcc(wifidrv_scan_result_handler, NULL) != RTW_SUCCESS)
  {
    return WL_FAILURE;
  }

  do
  {
    delay(1);
  } while ((_networkCount == 0) && (--attempts > 0));
  return _networkCount;
}
