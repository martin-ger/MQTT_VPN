#ifndef __MQTT_IF_H__
#define __MQTT_IF_H__

struct mqtt_if_data;

struct mqtt_if_data *mqtt_if_init(char * broker, IPAddress ipaddr);
struct mqtt_if_data *mqtt_if_init(char * broker, int port, char *topic_pre, IPAddress ipaddr, IPAddress netmask, IPAddress gw);

void mqtt_if_del(struct mqtt_if_data *data);

void mqtt_if_subscribe(struct mqtt_if_data *data);
void mqtt_if_unsubscribe(struct mqtt_if_data *data);

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
