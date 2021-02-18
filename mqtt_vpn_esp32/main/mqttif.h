#ifndef __MQTT_IF_H__
#define __MQTT_IF_H__

#include <lwip/ip.h>

#define MQTTIF_DIRECT_INPUT 0

struct mqtt_if_data;

struct mqtt_if_data *mqtt_vpn_if_init(char * broker, char* user, char* broker_password, char *topic_pre, char* password, ip4_addr_t ipaddr, ip4_addr_t netmask, ip4_addr_t gw);

void mqtt_if_del(struct mqtt_if_data *data);

void mqtt_if_add_reading_topic(struct mqtt_if_data *data, IPAddress addr);
void mqtt_if_flush_reading_topic(struct mqtt_if_data *data);

void mqtt_if_subscribe(struct mqtt_if_data *data);
void mqtt_if_unsubscribe(struct mqtt_if_data *data);
void mqtt_if_set_password(struct mqtt_if_data *data, char *password);

void mqtt_if_set_ipaddr(struct mqtt_if_data *data, uint32_t addr);
void mqtt_if_set_netmask(struct mqtt_if_data *data, uint32_t addr);
void mqtt_if_set_gw(struct mqtt_if_data *data, uint32_t addr);
void mqtt_if_set_up(struct mqtt_if_data *data);
void mqtt_if_set_down(struct mqtt_if_data *data);
void mqtt_if_set_mtu(struct mqtt_if_data *data, int mtu);
void mqtt_if_set_flag(struct mqtt_if_data *data, int flag);
void mqtt_if_clear_flag(struct mqtt_if_data *data, int flag);
void mqtt_if_clear_dns(void);
void mqtt_if_add_dns(uint32_t addr);

#endif