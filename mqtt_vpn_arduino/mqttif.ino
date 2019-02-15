#include "mqttif.h"

#include "MQTT.h"

#include <lwip/ip.h>
#include <lwip/init.h>
#include <lwip/dns.h>

struct mqtt_if_data {
  struct netif netif;
  ip_addr_t ipaddr;
  MQTT_Client *mqttcl;
  char *topic_pre;
  char *receive_topic;
  char *broadcast_topic;
  u_char buf[2048];
};

MQTT_Client mqttClient;
struct mqtt_if_data *mqtt_if;

void mqtt_if_input(struct mqtt_if_data *data, const char* topic, uint32_t topic_len, const char *mqtt_data, uint32_t mqtt_data_len);
struct mqtt_if_data *mqtt_if_add(MQTT_Client *cl, char *topic_pre);

static void mqttConnectedCb(uint32_t *args)
{
  mqtt_if_subscribe(mqtt_if);
}

static void mqttDisconnectedCb(uint32_t *args)
{
  mqtt_if_unsubscribe(mqtt_if);
}

static void mqttDataCb(uint32_t *args, const char* topic, uint32_t topic_len, const char *data, uint32_t data_len)
{
  //Serial.print("Got "); Serial.print(data_len); Serial.println("b input");
  mqtt_if_input(mqtt_if, topic, topic_len, data, data_len);
}

struct mqtt_if_data *mqtt_if_init(char * broker, int port, char *topic_pre, IPAddress ipaddr, IPAddress netmask, IPAddress gw) {
  Serial.print("Init on broker: "); Serial.println(broker);

  MQTT_InitConnection(&mqttClient, (uint8_t *)broker, port, 0);
//MQTT_InitClient(&mqttClient, MQTT_CLIENT_ID, MQTT_USER, MQTT_PASS, MQTT_KEEPALIVE, MQTT_CLEAN_SESSION);
  MQTT_InitClient(&mqttClient, (uint8_t *)"MQTT_VPN_X", 0, 0, 120, 1);

  MQTT_OnConnected(&mqttClient, mqttConnectedCb);
  MQTT_OnDisconnected(&mqttClient, mqttDisconnectedCb);
//MQTT_OnPublished(&mqttClient, mqttPublishedCb);
  MQTT_OnData(&mqttClient, mqttDataCb);
  
  mqtt_if = mqtt_if_add(&mqttClient, topic_pre);
  mqtt_if_set_ipaddr(mqtt_if, ipaddr);
  mqtt_if_set_netmask(mqtt_if, netmask);
  mqtt_if_set_gw(mqtt_if, gw);
  mqtt_if_set_up(mqtt_if);

  MQTT_Connect(&mqttClient);
  
  return mqtt_if;
}

struct mqtt_if_data *mqtt_if_init(char * broker, IPAddress ipaddr) {
  return mqtt_if_init(broker, 1883, "mqttip", ipaddr, IPAddress (255,255,255,0), IPAddress (0,0,0,0));
}

static err_t ICACHE_FLASH_ATTR
mqtt_if_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr)
{
struct mqtt_if_data *data = (struct mqtt_if_data *)netif->state;
struct ip_hdr *iph;
int len;
char buf[os_strlen((const char *)data->topic_pre) + 20];

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
	iph = (struct ip_hdr *)data->buf;

	//os_printf("packet %d, buf %x\r\n", len, p);
	//os_printf("to: " IPSTR " from: " IPSTR " via " IPSTR "\r\n", IP2STR(&iph->dest), IP2STR(&iph->src), IP2STR(ipaddr));
	os_sprintf(buf, "%s/" IPSTR , data->topic_pre, IP2STR(ipaddr));

	MQTT_Publish(data->mqttcl, (const char*)buf, (const char*)data->buf, len, 0, 1);

	return 0;
}

void ICACHE_FLASH_ATTR mqtt_if_input(struct mqtt_if_data *data, const char* topic, uint32_t topic_len, const char *mqtt_data, uint32_t mqtt_data_len)
{
  uint8_t buf[topic_len+1];
  os_strncpy((char *) buf, topic, topic_len);
  buf[topic_len] = '\0';
  //os_printf("Received %s - %d bytes\r\n", buf, mqtt_data_len);

  if ((topic_len == os_strlen((const char*)data->receive_topic) && os_strncmp((const char*)topic, (const char*)data->receive_topic, topic_len) == 0) || 
      (topic_len == os_strlen((const char*)data->broadcast_topic) && os_strncmp((const char*)topic, (const char*)data->broadcast_topic, topic_len) == 0)) {

	struct pbuf *pb = pbuf_alloc(PBUF_LINK, mqtt_data_len, PBUF_RAM);

	//os_printf("pb: %x len: %d tot_len: %d\r\n", pb, pb->len, pb->tot_len);

 	if (pb != NULL) {
		pbuf_take(pb, mqtt_data, mqtt_data_len);
		if (data->netif.input(pb, &data->netif) != ERR_OK) {
			pbuf_free(pb);
		}
	}
  }
}

static err_t ICACHE_FLASH_ATTR
mqtt_if_init(struct netif *netif)
{
	NETIF_INIT_SNMP(netif, snmp_ifType_other, 0);
	netif->name[0] = 'm';
	netif->name[1] = 'q';

	netif->output = mqtt_if_output;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct mqtt_if_data ICACHE_FLASH_ATTR *
mqtt_if_add(MQTT_Client *cl, char *topic_prefix)
{
	struct mqtt_if_data *data;

	data = (struct mqtt_if_data *)calloc(1, sizeof(*data));
	data->mqttcl = cl;

	data->topic_pre = (char *)malloc(os_strlen((const char*)topic_prefix)+1);
	os_strcpy(data->topic_pre, (const char*)topic_prefix);

	data->receive_topic = (char *)malloc(os_strlen((const char*)topic_prefix) + 20);
	os_sprintf(data->receive_topic, "%s/0.0.0.0", data->topic_pre);
	data->broadcast_topic = (char *)malloc(os_strlen((const char*)topic_prefix) + 20);
	os_sprintf(data->broadcast_topic, "%s/255.255.255.255", data->topic_pre);

  Serial.print("receive_topic : "); Serial.println(data->receive_topic);
  Serial.print("broadcast_topic : "); Serial.println(data->broadcast_topic);

	netif_add(&data->netif, NULL, NULL, NULL, data, mqtt_if_init, ip_input);
//	netif_set_default(&data->netif);
	return data;
}

void ICACHE_FLASH_ATTR
mqtt_if_del(struct mqtt_if_data *data)
{
	mqtt_if_set_down(data);
	netif_remove(&data->netif);
	free(data->topic_pre);
	free(data->receive_topic);
	free(data->broadcast_topic);
	free(data);
}

void ICACHE_FLASH_ATTR
mqtt_if_subscribe(struct mqtt_if_data *data)
{
	MQTT_Subscribe(data->mqttcl, data->receive_topic, 0);
	MQTT_Subscribe(data->mqttcl, data->broadcast_topic, 0);
  Serial.println("Subscribed");

	data->netif.flags != NETIF_FLAG_LINK_UP;
}

void ICACHE_FLASH_ATTR
mqtt_if_unsubscribe(struct mqtt_if_data *data)
{
	MQTT_UnSubscribe(data->mqttcl, data->receive_topic);
	MQTT_UnSubscribe(data->mqttcl, data->broadcast_topic);
  Serial.println("UnSubscribed");

	data->netif.flags &= ~NETIF_FLAG_LINK_UP;
}

void ICACHE_FLASH_ATTR
mqtt_if_set_ipaddr(struct mqtt_if_data *data, uint32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_ipaddr(&data->netif, &ipaddr);
	data->ipaddr = ipaddr;

	os_sprintf(data->receive_topic, "%s/" IPSTR, (char *)data->topic_pre, IP2STR(&data->ipaddr));
}

void ICACHE_FLASH_ATTR
mqtt_if_set_netmask(struct mqtt_if_data *data, uint32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_netmask(&data->netif, &ipaddr);
}

void ICACHE_FLASH_ATTR
mqtt_if_set_gw(struct mqtt_if_data *data, uint32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_gw(&data->netif, &ipaddr);
}

void ICACHE_FLASH_ATTR
mqtt_if_set_up(struct mqtt_if_data *data)
{
	netif_set_up(&data->netif);
}

void ICACHE_FLASH_ATTR
mqtt_if_set_down(struct mqtt_if_data *data)
{
	netif_set_down(&data->netif);
}

void ICACHE_FLASH_ATTR
mqtt_if_set_mtu(struct mqtt_if_data *data, int mtu)
{
	data->netif.mtu = mtu;
}

void ICACHE_FLASH_ATTR
mqtt_if_set_flag(struct mqtt_if_data *data, int flag)
{
	data->netif.flags |= flag;
}

void ICACHE_FLASH_ATTR
mqtt_if_clear_flag(struct mqtt_if_data *data, int flag)
{
	data->netif.flags &= ~flag;
}

static int dns_count;

void ICACHE_FLASH_ATTR
mqtt_if_clear_dns(void)
{
	ip_addr_t addr;
//	addr.addr = INADDR_ANY;
	int i;
	for (i = 0; i < DNS_MAX_SERVERS; i++)
		dns_setserver(i, &addr);
	dns_count = 0;
}

void ICACHE_FLASH_ATTR
mqtt_if_add_dns(uint32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	dns_setserver(dns_count++, &ipaddr);
}
