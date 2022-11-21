# MQTT_VPN
VPN over MQTT

The idea of this project is to enable bidirectional IP connectivity, where it is not available otherwise, e.g. if one node is hidden behind (several layers of) NAT. This is the case in most private networks and also in mobile IP networks. Prerequisite is, that all connected nodes can reach a common MQTT broker. This allows you to "dial-in" into an IoT device sitting anywhere in the internet.

On all connected clients it sets up a simple (optionally encrypted) IP network where all clients connected to the same MQTT broker can communicate with each other via IP (IPv6 is not yet working). IP is tunneled via MQTT. On the nodes it creates a TUN interface, assignes an IP address, and publishes all packets to an MQTT topic mqttip/[dest IP address]. At the same time it subscribes to an MQTT topic mqttip/[own IP address]. This establishes a fully connected IP network. "Switching" is done via the pub/sub mechanism of the MQTT broker.

## Security
Encryption and authentication is implemented via a preshared password for all clients of this VPN, similar to a WiFi key. This password is a parameter of the interface initialization. It it hashed to a symmetic key used for encrypting and decrypting each packet. Using the "crypto_secretbox" of libnacl, a well-established crypto lib (https://nacl.cr.yp.to/ ), each message is now encrypted and authenticated as one coming from another client of the VPN network segment. Each encrypted packet includes a 192 bit random nonce, this guarantees that even identical packets will be encrypted differently.

With encryption in place, an adversary controlling the MQTT broker or the network can still observe the traffic pattern (who is when sending packets to whom) and packet lengths as well as replaying single packets, but he won't be able to decode any packet or send own packets.

## Arduino ESP8266
In the mqtt_vpn_arduino directory you find a library for ESP8266 Arduino. Just download the zip-file, extract it, and drop the mqtt_vpn_arduino directory into the libraries directory of your Arduino ESP8266 installation.

Usage:
```
#include <ESP8266WiFi.h>
#include "mqttif.h"

...

IPAddress mqtt_vpn_addr(10,0,1,2);
struct mqtt_if_data *mqtt_if_init("broker", mqtt_vpn_addr, "password");
```

For more parameters for the initialization of the VPN you can also call:
```
struct mqtt_if_data *mqtt_if_init(char * broker, IPAddress ipaddr, char* password);
struct mqtt_if_data *mqtt_if_init(char * broker, char* user, char* broker_password, IPAddress ipaddr, char* password);
struct mqtt_if_data *mqtt_if_init(char * broker, char* user, char* broker_password, int port, char *topic_pre, char* password, IPAddress ipaddr, IPAddress netmask, IPAddress gw);

```

The sample "mqtt_vpn_telnet" is derived from the standard WiFiTelnetToSerial sample. The only difference is that it calls:
```
  my_if = mqtt_if_init(broker, mqtt_vpn_addr, vpn_password);
```
is its setup() function. This sets up the new "mqttif" interface with the IP over MQTT tunneling. Now you can ping or telnet into the ESP8266 via the VPN from another ESP8266 using the same SW or from a linux box using the small programm below. If you give an empty password with "" encryption will be disabled. The demo sketch uses the hardcoded password "secret" and address 10.0.1.2/24. 

The sample "mqtt_vpn_webserver" is derived in the same way from the standard EPS8266WebServer/HelloServer sample. Here you have to edit WiFi SSID/password and the broker name/address. Now you can open "10.0.1.2" with a browser on a linux box (given that you have started the MQTT_VPN client there as shown in the linux section below).

The sample "mqtt_vpn_nat" is derived from the standard RangeExtender-NAPT and allows you to contact, via the VPN tunnel, another host (the hard-coded address 172.16.0.100, adapt it to your needs) within the ESP8266 wifi network (the ESP is connected as STA). You can call ```mqtt_if_add_reading_topic``` multiple times to allow the ESP to forward packets to multiple hosts. Please note that an upper limit of 8 hosts exists in the source tree (```mqttif.c``` defines a max of ```N_ADDR_MAX=10``` topics (=ESP address in the tunnel + broadcast + 8 addresses) to be subscribed on the MQTT server).

## ESP32 (ESP-IDF)

In the mqtt_vpn_esp32 directory you find an implementation for the ESP32 and the ESP-IDF environment. The project is a clone of the webserver example and it is enhanced by the three files "mqttif.c", "mqttif.h", and "event_source.h" that implement the MQTT_VPN. In "main.c" you will find the additional lines:
```
#include "mqttif.h"

...

ip4_addr_t ipaddr;
ip4_addr_t netmask;
ip4_addr_t gw;

IP4_ADDR(&ipaddr, 10,0,1,2);
IP4_ADDR(&netmask, 255,255,255,0);
IP4_ADDR(&gw, 0,0,0,0);

mqtt_vpn_if_init("mqtt://mybroker.org:1883", "", "", "mqttip", "secret", ipaddr, netmask, gw);
```

Build it with the usual "make menuconfig" to configure ssid and password for the sample.

## Linux

This Linux version can communicate with the Arduino and the ESP32 version above. Run this prog in background and use all standard network tools (including wireshark).
If you start for example:
```
sudo ./mqtt_vpn -i mq0 -a 10.0.1.1 -b tcp://my_broker.org:1883 -k secret -d
```
You will see with "ifconfig" a new network interface "mq0" with address 10.0.1.1. It is connected via the broker to all other devices using the VPN over MQTT. Now you can reach an ESP8266 running the program above with
```
telnet 10.0.1.2 23
```

Usage:
```
mqtt_vpn -i <if_name> -a <ip> -b <broker> [-m <netmask>] [-n <clientid>] [-d]

-i <if_name>: Name of interface to use (mandatory)
-a <ip>: IP address of interface to use (mandatory)
-b <broker>: Address of MQTT broker (like: tcp://broker.io:1883) (mandatory)
-m <netmask>: Netmask of interface to use (default 255.255.255.0)
-u <username>: user of the MQTT broker
-p <password>: password of the MQTT broker user
-k <password>: preshared key for all clients of this VPN (no password = no encryption, default)
-6 <ip6>: IPv6 address of interface to use
-x <prefix>: prefix length of the IPv6 address (default 64)
-n <clientid>: ID of MQTT client (MQTT_VPN_<random>)
-t <ip>: IP address of a target to NAT
-d: outputs debug information while running
-h: prints this help text
```

Requires the Paho MQTT C Client Library (https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/index.html ) and the libnacl for the crypto operations.

See mqttVPNdependencyInstaller.sh for help building/installing the libs. Just do `sudo chmod +x ./mqttVPNdependencyInstaller.sh` to enable it to execute. It will go all the way through and also run the make command to build the target executable "mqtt_vpn" which you then simply run as:
`sudo ./mqtt_vpn`

## Future Issues
- IPv6 as VPN

## Thanks
- tuanpmt for esp_mqtt (https://github.com/tuanpmt/esp_mqtt )
