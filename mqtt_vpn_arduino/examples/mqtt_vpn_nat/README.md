# MQTT_VPN_NAT

This works assumes you have a topology like :
computerA (192.168.0.10/24) <--> router <--WAN--> router <--> {ESP-VPN (172.16.0.50/24) + computerB (172.16.0.100/24)}
And supposes you want to connect from computerA to computerB without any modification to any router nor computerB. ComputerB will have its own gw, etc.

## setup computerA
You need to run mqtt_vpn and set a route to 172.16.0.0/24 through the VPN tunnel :
in one terminal :
```sudo ./mqtt_vpn -i mq0 -a 10.0.1.1 -b tcp://my_broker.org:1883 -k secret -d```
and in another :
```sudo ip route add 172.16.0.0/24 via 10.0.1.2```

## setup ESP-VPN
You have to set the ```mqtt_vpn_target_addr``` according to the address of computerB

## connect through the tunnel
when ESP-VPN is up, you just need to send packets to computerB, profits !

## how does this works
In the following [IP1|IP2] refers to a packet with IP1 as source address and IP2 as destination address.

1. computerA sends a packet [10.0.1.1|172.16.0.100] through the tunnel by publishing a message on the broket in the topic .../172.16.0.100
2. ESP-VPN can read this message (it subscribes to it) and since it is not the destination will use the NAT to follow up in the wifi LAN
3. a packet [172.16.0.50|172.16.0.100] is inside the LAN wifi due to NAT
4. computerB can replies directly to ESP-VPN (packet reply : [172.16.0.100|172.16.0.50])
5. ESP-VPN looks in its NAT table and forward it back in the VPN tunnel (message [172.16.0.100|10.0.1.1])
