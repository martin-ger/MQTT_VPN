/*
 *   This sketch is a demo for the MQTT_VPN
 *   Edit the "..." lines in the config for your environment
 */

#include <ESP8266WiFi.h>
#include "mqttif.h"

// WiFi settings
const char* ssid     = "...";
const char* password = "...";

// VPN settings
char* broker = "...";
char* vpn_password = "secret";
IPAddress mqtt_vpn_addr(10,0,1,2);

struct mqtt_if_data *my_if;

#define MAX_SRV_CLIENTS 1
WiFiServer server(23);
WiFiClient serverClients[MAX_SRV_CLIENTS];

void setup() {
  Serial.begin(115200);
  delay(10);

  // We start by connecting to a WiFi network

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());

  /* The magic is here:
     This sets up a new IP interface that is connected to the central MQTT broker */
  my_if = mqtt_if_init(broker, mqtt_vpn_addr, vpn_password);

  server.begin();
  server.setNoDelay(true);

  Serial.print("MQTT VPN ready! Use 'telnet ");
  Serial.print(mqtt_vpn_addr);
  Serial.println(" 23' to connect");
}

int value = 0;

void loop() {
  uint8_t i;
  //check if there are any new clients
  if (server.hasClient()) {
    for (i = 0; i < MAX_SRV_CLIENTS; i++) {
      //find free/disconnected spot
      if (!serverClients[i] || !serverClients[i].connected()) {
        if (serverClients[i]) {
          serverClients[i].stop();
        }
        serverClients[i] = server.available();
        Serial1.print("New client: "); Serial1.print(i);
        break;
      }
    }
    //no free/disconnected spot so reject
    if (i == MAX_SRV_CLIENTS) {
      WiFiClient serverClient = server.available();
      serverClient.stop();
      Serial1.println("Connection rejected ");
    }
  }
  //check clients for data
  for (i = 0; i < MAX_SRV_CLIENTS; i++) {
    if (serverClients[i] && serverClients[i].connected()) {
      if (serverClients[i].available()) {
        //get data from the telnet client and push it to the UART
        while (serverClients[i].available()) {
          Serial.write(serverClients[i].read());
        }
      }
    }
  }
  //check UART for data
  if (Serial.available()) {
    size_t len = Serial.available();
    uint8_t sbuf[len];
    Serial.readBytes(sbuf, len);
    //push UART data to all connected telnet clients
    for (i = 0; i < MAX_SRV_CLIENTS; i++) {
      if (serverClients[i] && serverClients[i].connected()) {
        serverClients[i].write(sbuf, len);
        delay(1);
      }
    }
  }
}
