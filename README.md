# MQTT_VPN
VPN over MQTT

The idea of this project is to enable bidirectional IP connectivity, where it is not available otherwise, e.g. if one node is hidden behind (several layers of) NAT. This is the case in most private networks and also in mobile IP networks. Prerequisite is, that all connected nodes can reach a common MQTT broker. This allows you to "dial-in" into an IoT device sitting anywhere in the internet.

On all connected clients it sets up a simple (not yet encoded) IP network where all clients connected to the same MQTT broker can communicate with each other via IP (IPv6 is not yet working). IP is tunneled via MQTT. On the nodes it creates a TUN interface, assignes an IP address, and publishes all packets to an MQTT topic mqttip/[dest IP address]. At the same time it subscribes to an MQTT topic mqttip/[own IP address]. This establishes a fully connected IP network. "Switching" is done via the pub/sub mechanism of the MQTT broker.

## Security
Encryption and authentication is implemented via a preshared password for all clients of this VPN, similar to a WiFi key. This password is a parameter of the interface initialization. It it hashed to a symmetic key used for encrypting and decrypting each packet. Using the "crypto_secretbox" of libnacl, a well-established crypto lib (https://nacl.cr.yp.to/ ), each message is now encrypted and authenticated as one coming from another client of the VPN network segment. Each encrypted packet includes a 192 bit random nonce, this guarantees that even identical packets will be encrypted differently.

With encryption in place, an adversary controlling the MQTT broker or the network can still observe the traffic pattern (who is when sending packets to whom) and packet lengths as well as replaying single packets, but he won't be able to decode any packet or send own packets.

## Arduino ESP8266
In the mqtt_vpn_arduino directory you will find a sample sketch and all required lib files. The sample "mqtt_vpn_arduino.ino" is derived from the standard WiFiTelnetToSerial sample. The only difference is, that it calls:
```
  my_if = mqtt_if_init(broker, mqtt_vpn_addr, vpn_password);
```
is its setup() function. This sets up the new "mqttif" interface with the IP over MQTT tunneling. Now you can ping or telnet into the ESP8266 via the VPN from another ESP8266 using the same SW or from a linux box using the small programm below. If you give an empty password with "" encryption will be disabled. The demo sketch uses the hardcoded password "secret" and address 10.0.1.2/24. 

BTW: Another ESP8266 version can be found in the mqtt_tun branch of the esp_wifi_repeater (https://github.com/martin-ger/esp_wifi_repeater/tree/mqtt_tun )

## Linux

This Linux version can communicate with the Arduino version above. Run this prog in background and use all standard network tools (including wireshark).
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
-k <password>: preshared key for all clients of this VPN (no password = no encryption, default)
-6 <ip6>: IPv6 address of interface to use
-p <prefix>: prefix length of the IPv6 address (default 64)
-n <clientid>: ID of MQTT client (MQTT_VPN_<random>)
-d: outputs debug information while running
-h: prints this help text
```

Requires the Paho MQTT C Client Library (https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/index.html ) and the libnacl for the crypto operations.

## Future Issues
- IPv6 as VPN

## Thanks
- tuanpmt for esp_mqtt (https://github.com/tuanpmt/esp_mqtt )
- Ingo Randolf for esp-mqtt-arduino (https://github.com/i-n-g-o/esp-mqtt-arduino)
