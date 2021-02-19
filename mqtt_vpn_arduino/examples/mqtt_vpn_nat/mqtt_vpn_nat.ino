/*
 *   This sketch is a demo for the MQTT_VPN
 *   Edit the "..." lines in the config for your environment
 */

#include <ESP8266WiFi.h>
#include <mqttif.h>
#include <lwip/napt.h>
#include <lwip/dns.h>

// WiFi settings
const char* ssid     = "...";
const char* password = "...";

// VPN settings
char* broker = "...";
char* vpn_password = "secret";
int broker_port = 1883;
IPAddress mqtt_vpn_addr(10,0,1,2);

/* 
 *   The following address must point to another machine
 *   which will also be fully accessible, via the vpn tunnel,
 *   by the host on the other side of the tunnel.
 *   We will NAT every packets destinated to this address
 *   on our local wifi network with the ip_napt_enable call.
 *   This should be set consistently with WiFi.localIP()
 */
IPAddress mqtt_vpn_target_addr(172,16,0,100);

// Broker settings
char* broker_username = "...";
char* broker_password = "...";
char* broker_topic_prefix = "...";

struct mqtt_if_data *my_if;

#define NAPT 1
#define NAPT_PORT 10

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
  my_if = mqtt_if_init(broker, broker_username, broker_password, broker_port, broker_topic_prefix, vpn_password, mqtt_vpn_addr, IPAddress(255, 255, 255, 0), IPAddress(0, 0, 0, 0));
  mqtt_if_add_reading_topic(my_if,  mqtt_vpn_target_addr);

  Serial.printf("Heap before: %d\r\n", ESP.getFreeHeap());
  err_t ret = ip_napt_init(NAPT, NAPT_PORT);
  Serial.printf("ip_napt_init(%d,%d): ret=%d (OK=%d)\r\n", NAPT, NAPT_PORT, (int)ret, (int)ERR_OK);
  if (ret == ERR_OK) {
    ret = ip_napt_enable(mqtt_vpn_addr, 1);
    Serial.printf("ip_napt_enable_no(my_if): ret=%d (OK=%d)\r\n", (int)ret, (int)ERR_OK);
    if (ret == ERR_OK) {
      Serial.printf("WiFi Network MQTT_VPN is now NATed behind '%s'\r\n", ssid);
    }
  }
  Serial.printf("Heap after napt init: %d\r\n", ESP.getFreeHeap());
  if (ret != ERR_OK) {
    Serial.printf("NAPT initialization failed\r\n");
  }
}

void loop() {

}
