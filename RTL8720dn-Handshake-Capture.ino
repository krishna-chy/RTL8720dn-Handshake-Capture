/*
 * Deauth made possible by tesa-kelebeband. https://github.com/tesa-klebeband/
 * Sniffer code by Nickguitar. https://github.com/Nickguitar/
 * Forked by Cancro29. https://github.com/Cancro29/
 * 
 * ABOUT
 * This program captures WPA/WPA2 4-way handshake that performed during reauthentication and stores it as PCAP file
 * HOW IT WORKS
 * When attack is started, RTL8720dn sends deauthentication packets to the target AP. Affected clients will get disconnected
 * and will attempt to reconnect. During reconnect, RTL8720dn will sniff for EAPOL frames. Captured data will be served as downloadable PCAP file
 * 
 * See defines.h to configure this code
 */


#include <WiFi.h>
#include <wifi_conf.h>
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "vector"
#include "map"
#include "wifi_cust_tx.h"
#include "defines.h"
#include "handshake.h"
#include "webserver.h"

void setup() {
  Serial.begin(115200);

  Serial.println("AP:" + AP_SSID);
  Serial.println(AP_SSID.length());
  Serial.println("Pass:" + AP_Password);
  Serial.println(AP_Password.length());

  AP_SSID.toCharArray(ap_ssid, 33);
  AP_Password.toCharArray(ap_pass, 33);
  AP_Channel.toCharArray(ap_channel, 4);

  status = WiFi.apbegin(ap_ssid, ap_pass, ap_channel, ssid_status);
  if (status == WL_CONNECTED) {
    Serial.println(F("AP Started!"));
  } else {
    Serial.println(F("Failed to start AP!"));
    while (true)
      ;  // Halt execution if AP fails to start
  }
  
  webServer.begin();
  performScan();
}

void loop() {
  webServer_handleClient();
  if (readyToSniff == true){deauthAndSniff();}
}

void performScan(){
  uint8_t ap_count_list[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  int32_t peak_list[] = {RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR, RSSI_FLOOR};
    // int16_t peak_id_list[] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

  int32_t channel;
  uint16_t idx;
  int32_t rssi;
  String ssid;

  // int16_t offset;
    // scan for existing networks:
    Serial.println(F("/////////////////////// Scanning available networks..."));
    int n = scanNetworks();
    if (n == 0)
    {
      Serial.println(F("No networks found"));
    }
    else
    {
      for (int i = 0; i < n; i++)
      {
        channel = _networkChannel[i];
        idx = channelIdx(channel);
        rssi = _networkRssi[i];

        // channel peak stat
        if (peak_list[idx] < rssi)
        {
          peak_list[idx] = rssi;
          // peak_id_list[idx] = i;
        }

        ap_count_list[idx]++;
      }


      //Serial.print(n);
      //Serial.println(" networks (2.4 GHz)");
      for (idx = 0; idx < 14; idx++)
      {
        channel = channel_legend[idx];
        // offset = (idx + 2) * channel24_width;
        if (channel > 0)
        {
          //Serial.print(channel);
        }
        if (ap_count_list[idx] > 0)
        {
          //Serial.println(ap_count_list[idx]);
        }
      }

      //Serial.println("");
      //Serial.println(" networks (5 GHz)");
      // draw 5 GHz graph base axle
      for (idx = 14; idx < 71; idx++)
      {
        channel = channel_legend[idx];
        // offset = (idx - 14 + 2) * channel50_width;
        if (channel > 0)
        {
         
          //Serial.println(channel);
        }
        if (ap_count_list[idx] > 0)
        {
          //Serial.print(ap_count_list[idx]);
        }
      }

    }
  }
