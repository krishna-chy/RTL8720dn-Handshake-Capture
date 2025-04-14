void webServer_handleClient() {
  WiFiClient client = webServer.available();
    if (client.connected()) {

    String request = client.readStringUntil('\r'); // Read the request line
    Serial.print(F("Request: "));
    Serial.println(request);

    if (request == ""){Serial.print(F("Invalid reuqest"));return;}

    String fullPath = "";
    // Parse the request
    Serial.println("Parsing request...");
    if (request.startsWith("GET ") || request.startsWith("POST ")) {
      int pathStart = request.indexOf(' ') + 1; // Start of the URL
      int pathEnd = request.indexOf(' ', pathStart); // End of the URL
      String fullPath = request.substring(pathStart, pathEnd);

      Serial.print("Full path: ");
      Serial.println(fullPath);

      if (fullPath == "/"){
        
      }
      if (fullPath == "/"){
          Serial.println("Serving main page");
          String header = F("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
          client.print(header);
          client.print("<html><body>");
          client.print("<h1>BW16 HANDSHAKE CAPTURE</h1>");
          client.print("<p>Deauth made possible by tesa-kelebeband. https://github.com/tesa-klebeband/</p>");
          client.print("<p>Sniffer code by Nickguitar. https://github.com/Nickguitar/</p>");
          client.print("<p>Forked by Cancro29. https://github.com/Cancro29/</p>");
          client.print("<form style='display:inline-block; padding-left:8px;' method='post' action='/?scan=scan'><button>Scan</button></form>");
          
          if (isHandshakeCaptured == true){client.print("<form method='post' action='/get_pcap'><button>Get PCAP</button></form>");}
          else if (isHandshakeCaptured == false && _selectedNetwork.ssid != "") {client.print("<form method='post' action='/?handshake=capture'><button>Capture Handshake</button></form>");}

          
          
          client.print("<table>");
          client.print("<tr style='horizontal-align:top'><th style='width:0%;'>SSID</th><th style='width:0%;'>BSSID</th><th style='width:0%;'>CH</th><th style='width:0%;'>SIGNAL</th><th style='width:0%;'>SELECT</th></tr> ");
          
          for (int i=0;i < 32;i++)
              {
                if (String(_networks[i].ssid) == ""){continue;}
                //Serial.println(_networks[i].ssid);
                
                if (_networks[i].band == "5 Ghz"){client.print("<tr><td>");}
                else {client.print("<tr><td>");}
                if (_networks[i].band == "5 Ghz"){client.print("[5Ghz] ");client.print(String(_networks[i].ssid));}
                else {client.print(String(_networks[i].ssid));}
                client.print("</td><td>");
                client.print(bytesToStr(_networks[i].bssid,6));
                client.print("</td><td>");
                client.print(String(_networks[i].ch));
                client.print("</td><td>");
                client.print(String(_networks[i].rs) + " %");
                client.print("</td>");
          
                client.print("<td>");
                client.print("<form style='margin: 2;padding: 0;' method='post' action='/?ap=");
                client.print(String(bytesToStr(_networks[i].bssid, 6)));
                client.print("'>");
          
                bool isSelected = false;
          
                //Serial.println(bytesToStr(_networks[i].bssid, 6) + " || " + bytesToStr(_selectedNetwork_array[i].bssid, 6));
                
                if (bytesToStr(_networks[i].bssid, 6) == bytesToStr(_selectedNetwork.bssid, 6)) {isSelected = true;Serial.println("Match");}
          
                if (isSelected == true){client.print("<button style='background-color: #0e62c2; color:black;'>Select</button></form>");}
                else {client.print("<button>Select</button></form>");}
                client.print("</td></tr>");

                
              }
              client.print("</table>");
              client.print("</div><br>");
              client.print("</body></html>");
              client.print("\r\n\r\n");
              client.stop();
              return;
     
      }
      if (fullPath == "/get_pcap"){
          Serial.println("Serving PCAP file");
          // Send HTTP headers.
          client.println("HTTP/1.1 200 OK");
          client.println("Content-Type: application/octet-stream");
          client.println("Content-Disposition: attachment; filename=\"capture.pcap\"");
          client.println("Connection: close");
          client.println();
          
          // --- FIX ---
          size_t chunkSize = 1460; // Common TCP Maximum Segment Size, adjust as needed
          for (size_t i = 0; i < pcapData.size(); i += chunkSize) {
              size_t currentChunkSize = min(chunkSize, pcapData.size() - i);
  
              // Optional: Add #undef write here if needed
               #ifdef write
               #undef write
               #endif
  
              // Send the current chunk
              client.write(pcapData.data() + i, currentChunkSize);
  
              // Optional: Add a small delay or yield() if needed on ESP platforms
              // delay(1); // or yield(); or delay(0);
          }
          // -----------
          return;
        }


    // Arguments handler
    // Check if there are arguments
      int queryStart = fullPath.indexOf('?');
      if (queryStart != -1) {
        String queryString = fullPath.substring(queryStart + 1); // Extract query string
        Serial.print("Query string: ");
        Serial.println(queryString);

        bool hasArguments = false;

        // Split arguments
        while (queryString.length() > 0) {
          int separatorIndex = queryString.indexOf('&');
          String pair;
          if (separatorIndex == -1) {
            pair = queryString; // Last or only argument
            queryString = "";
          } else {
            pair = queryString.substring(0, separatorIndex);
            queryString = queryString.substring(separatorIndex + 1);
          }

          // Split key-value pair
          int equalsIndex = pair.indexOf('=');
          if (equalsIndex != -1) {
            String key = pair.substring(0, equalsIndex);
            String value = pair.substring(equalsIndex + 1);
            Serial.print(F("Key: "));
            Serial.print(key);
            Serial.print(F(", Value: "));
            Serial.println(value);
            
            hasArguments = true; // At least one argument was found
            //handleArgument(client,key, value); // Call the argument handler


            // Process argument
            if (key == "ap"){
              
              for (int i=0;i < 32;i++){
                
                    if (value == bytesToStr(_networks[i].bssid, 6)){
                      Serial.println("Selected AP : " + _networks[i].ssid);
                      _selectedNetwork = _networks[i];
                    }
                    
              }
                String response = "HTTP/1.1 307 Temporary Redirect\n";
                response += "Location: /";
                client.print(response);
                return;
            }
         
            if (key == "handshake"){
                readyToSniff = true;

                
                String header = F("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
                client.print(header);
                client.print("<html><body>");
                client.print("<script>window.setTimeout(function(){window.location.href = 'http://192.168.1.1/';}, 10000);</script>");
                client.print("<br><br><br>");
                client.print("Please wait");
                client.print("</body></html>");
                return;
            }
            if (key == "scan"){
                String header = F("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
                client.print(header);
                client.print("<html><body>");
                client.print("<script>window.setTimeout(function(){window.location.href = 'http://192.168.1.1/';}, 12000);</script>");
                client.print("<br><br><br>");
                client.print("Scanning");
                client.print("</body></html>");
                performScan();
                return;
            }

            
          } else {
            Serial.print(F("Key: "));
            Serial.println(pair); // Argument without value
            hasArguments = true; // At least one argument was found
          }
        }

        if (hasArguments) {
          Serial.println(F("At least one argument was processed."));
        } else {
          Serial.println(F("No arguments found."));
        }
      }



      
    }
      
    }
}
