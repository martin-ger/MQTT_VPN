#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event_loop.h"
#include "esp_event_base.h"

#include "lwip/init.h"
#include "lwip/dns.h"

#include "mqtt_client.h"
#include "sodium.h"

#include "mqttif.h"
#include "event_source.h"

esp_event_loop_handle_t loop_with_task;

static const char *TAG = "MQTTIF";

struct mqtt_if_data
{
    struct netif netif;
    ip4_addr_t ipaddr;
    esp_mqtt_client_handle_t mqttcl;
    char *topic_pre;
    char *receive_topic;
    char *broadcast_topic;
    uint8_t key_set;
    u_char key[crypto_secretbox_KEYBYTES];
    //u_char buf[2048];
    char inbuf[2048];
    char intopic[128];
    int intopic_len;
    //u_char cypherbuf_buf[2048];
};

struct mqtt_pub_data
{
    char *topic;
    char *data_buf;
    int data_len;
};

struct mqtt_if_data *mqtt_if;

void mqtt_if_input(struct mqtt_if_data *data, const char *topic, uint32_t topic_len, const char *mqtt_data, uint32_t mqtt_data_len);
struct mqtt_if_data *mqtt_if_add(esp_mqtt_client_handle_t cl, char *topic_pre);


static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event)
{
    //esp_mqtt_client_handle_t client = event->client;
    // your_context_t *context = event->context;
    
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGD(TAG, "MQTT_EVENT_CONNECTED");

            mqtt_if_subscribe(mqtt_if);

            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGD(TAG, "MQTT_EVENT_DISCONNECTED");

            mqtt_if_unsubscribe(mqtt_if);

            break;

        case MQTT_EVENT_DATA:
            ESP_LOGD(TAG, "MQTT_EVENT_DATA");
            //ESP_LOGI(TAG, "TOPIC=%.*s", event->topic_len, event->topic);
            //ESP_LOGI(TAG, "DATA=%d bytes", event->data_len);
            //ESP_LOGI(TAG, "TOTAL_DATA=%d bytes", event->total_data_len);
            //ESP_LOGI(TAG, "OFFSET=%d bytes", event->current_data_offset);
            if (event->data_len == event->total_data_len)
            {
                mqtt_if_input(mqtt_if, event->topic, event->topic_len, event->data, event->data_len);
            }
            else
            {
                // Reassemble fragmented packets
                if (event->current_data_offset == 0)
                {
                    mqtt_if->intopic_len = event->topic_len;
                    strncpy(mqtt_if->intopic, event->topic, sizeof(mqtt_if->intopic));
                }
                if (event->current_data_offset + event->data_len <= sizeof(mqtt_if->inbuf))
                {
                    memcpy(mqtt_if->inbuf + event->current_data_offset, event->data, event->data_len);
                    if (event->current_data_offset + event->data_len == event->total_data_len)
                    {
                        mqtt_if_input(mqtt_if, mqtt_if->intopic, mqtt_if->intopic_len, mqtt_if->inbuf, event->total_data_len);
                    }
                }
            }

            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGD(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGD(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGD(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGD(TAG, "MQTT_EVENT_ERROR");
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
    }
    return ESP_OK;
}

ESP_EVENT_DEFINE_BASE(MQTTVPN_EVENTS)

static void packet_receive_handler(void* handler_args, esp_event_base_t base, int32_t id, void* event_data)
{
    struct pbuf *pb = *(struct pbuf **)event_data;
    if (pb == NULL)
        return;

    ESP_LOGD(TAG, "Buffer received - len: %d tot_len: %d", pb->len, pb->tot_len);
    if (mqtt_if->netif.input(pb, &mqtt_if->netif) != ERR_OK)
    {
        ESP_LOGI(TAG, "input failed");
        pbuf_free(pb);
    }
    //printf("End rcv: %d\n", xPortGetFreeHeapSize());
}

static void packet_send_handler(void* handler_args, esp_event_base_t base, int32_t id, void* event_data)
{
    struct mqtt_pub_data *pub_data = *(struct mqtt_pub_data **)event_data;
    if (pub_data == NULL)
        return;

    ESP_LOGI(TAG, "Send topic %s received - len: %d", pub_data->topic, pub_data->data_len);
    
    esp_mqtt_client_publish(mqtt_if->mqttcl, pub_data->topic, pub_data->data_buf, pub_data->data_len, 0, 0);

    free(pub_data->data_buf);
    free(pub_data->topic);
    free(pub_data);
    //printf("End snd: %d\n", xPortGetFreeHeapSize());
}

struct mqtt_if_data *mqtt_vpn_if_init(char *broker, char *user, char *broker_password, char *topic_pre, char *password, ip4_addr_t ipaddr, ip4_addr_t netmask, ip4_addr_t gw)
{
    ESP_LOGI(TAG, "Init on broker: %s", broker);

    esp_mqtt_client_config_t mqtt_cfg = {
        .uri = broker,
        .event_handle = mqtt_event_handler,
        // .user_context = (void *)your_context,
        .username = strlen(user)==0 ? NULL : user,
        .password = strlen(broker_password)==0 ? NULL : broker_password,
    };

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);

    mqtt_if = mqtt_if_add(client, topic_pre);
    mqtt_if_set_ipaddr(mqtt_if, ipaddr.addr);
    mqtt_if_set_netmask(mqtt_if, netmask.addr);
    mqtt_if_set_gw(mqtt_if, gw.addr);
    mqtt_if_set_up(mqtt_if);

    mqtt_if_set_password(mqtt_if, password);

    esp_event_loop_args_t loop_with_task_args = {
        .queue_size = 5,
        .task_name = "loop_task", // task will be created
        .task_priority = uxTaskPriorityGet(NULL),
        .task_stack_size = 4096,
        .task_core_id = tskNO_AFFINITY
    };

    // Create the event loops
    esp_event_loop_create(&loop_with_task_args, &loop_with_task);

    // Register the handler for task iteration event. Notice that the same handler is used for handling event on different loops.
    // The loop handle is provided as an argument in order for this example to display the loop the handler is being run on.
    esp_event_handler_register_with(loop_with_task, MQTTVPN_EVENTS, PACKET_RECEIVED_EVENT, packet_receive_handler, loop_with_task);
    esp_event_handler_register_with(loop_with_task, MQTTVPN_EVENTS, PACKET_SEND_EVENT, packet_send_handler, loop_with_task);

    esp_mqtt_client_start(client);

    return mqtt_if;
}


static err_t mqtt_if_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    struct mqtt_if_data *if_state = (struct mqtt_if_data *)netif->state;
    struct mqtt_pub_data *pub_data = (struct mqtt_pub_data *)malloc(sizeof(struct mqtt_pub_data));
    if (pub_data == NULL)
        return ERR_MEM;

    pub_data->topic = (char *)malloc(strlen((const char *)if_state->topic_pre) + 20);
    if (pub_data->topic == NULL) {
        free (pub_data);
        return ERR_MEM;
    }
    sprintf(pub_data->topic, "%s/" IPSTR, if_state->topic_pre, IP2STR(ipaddr));

    pub_data->data_buf = (char *)malloc(2048);
    if (pub_data->data_buf == NULL) {
        free (pub_data->topic);
        free (pub_data);
        return ERR_MEM;
    }

    if (if_state->key_set)
    {
        static char buf[2048];
        int len;

        randombytes((u_char *)pub_data->data_buf, crypto_secretbox_NONCEBYTES);
        bzero(buf, crypto_secretbox_ZEROBYTES);
        len = pbuf_copy_partial(p, buf + crypto_secretbox_ZEROBYTES, sizeof(buf) - crypto_secretbox_ZEROBYTES, 0);
        crypto_secretbox((u_char *)pub_data->data_buf + crypto_secretbox_NONCEBYTES, (u_char *)buf, len + crypto_secretbox_ZEROBYTES, (u_char *)pub_data->data_buf, if_state->key);
        pub_data->data_len = len + crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES;

        esp_event_post_to(loop_with_task, MQTTVPN_EVENTS, PACKET_SEND_EVENT, &pub_data, sizeof(&pub_data), portMAX_DELAY);
    }
    else
    {
        pub_data->data_len = pbuf_copy_partial(p, pub_data->data_buf, sizeof(pub_data->data_buf), 0);

        //struct ip_hdr *iph; = (struct ip_hdr *)data->buf;
        //printf("packet %d, buf %x\r\n", len, p);
        //printf("to: " IPSTR " from: " IPSTR " via " IPSTR "\r\n", IP2STR(&iph->dest), IP2STR(&iph->src), IP2STR(ipaddr));

        esp_event_post_to(loop_with_task, MQTTVPN_EVENTS, PACKET_SEND_EVENT, &pub_data, sizeof(&pub_data), portMAX_DELAY);
    }
    return ERR_OK;
}

void mqtt_if_input(struct mqtt_if_data *data, const char *topic, uint32_t topic_len, const char *mqtt_data, uint32_t mqtt_data_len)
{
    uint8_t buf[topic_len + 1];
    strncpy((char *)buf, topic, topic_len);
    buf[topic_len] = '\0';
    struct pbuf *pb;

    ESP_LOGI(TAG, "Received %s - %d bytes", buf, mqtt_data_len);

    if ((topic_len == strlen((const char *)data->receive_topic) && strncmp((const char *)topic, (const char *)data->receive_topic, topic_len) == 0) ||
        (topic_len == strlen((const char *)data->broadcast_topic) && strncmp((const char *)topic, (const char *)data->broadcast_topic, topic_len) == 0))
    {

        if (data->key_set)
        {
            if (mqtt_data_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES)
            {
                ESP_LOGI(TAG, "mqttif decrypt error (too short)");
                return;
            }

            unsigned char m[mqtt_data_len];
            uint32_t message_len = mqtt_data_len - crypto_secretbox_NONCEBYTES;

            if (crypto_secretbox_open(m, (const unsigned char *)(mqtt_data + crypto_secretbox_NONCEBYTES), message_len, (const unsigned char *)mqtt_data, data->key) == -1)
            {
                ESP_LOGI(TAG, "mqttif decrypt error");
                return;
            }

            pb = pbuf_alloc(PBUF_LINK, message_len - crypto_secretbox_ZEROBYTES, PBUF_RAM);
            if (pb == NULL)
                return;
            pbuf_take(pb, m + crypto_secretbox_ZEROBYTES, message_len - crypto_secretbox_ZEROBYTES);
        }
        else
        {
            pb = pbuf_alloc(PBUF_LINK, mqtt_data_len, PBUF_RAM);
            if (pb == NULL)
                return;
            pbuf_take(pb, mqtt_data, mqtt_data_len);
        }

        // Post it to the send handler
        ESP_LOGD(TAG, "Buffer post - len: %d tot_len: %d", pb->len, pb->tot_len);

#if !(MQTTIF_DIRECT_INPUT)
        esp_event_post_to(loop_with_task, MQTTVPN_EVENTS, PACKET_RECEIVED_EVENT, &pb, sizeof(pb), portMAX_DELAY);
#else
        if (mqtt_if->netif.input(pb, &mqtt_if->netif) != ERR_OK)
        {
            ESP_LOGI(TAG, "input failed");
            pbuf_free(pb);
        }
#endif
    }
}


static err_t mqtt_if_init(struct netif *netif)
{
    //NETIF_INIT_SNMP(netif, snmp_ifType_other, 0);
    netif->name[0] = 'm';
    netif->name[1] = 'q';

    netif->output = mqtt_if_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_LINK_UP;

    return 0;
}

struct mqtt_if_data *mqtt_if_add(esp_mqtt_client_handle_t cl, char *topic_prefix)
{
    struct mqtt_if_data *data;

    data = (struct mqtt_if_data *)calloc(1, sizeof(*data));
    data->mqttcl = cl;

    data->topic_pre = (char *)malloc(strlen((const char *)topic_prefix) + 1);
    strcpy(data->topic_pre, (const char *)topic_prefix);

    data->receive_topic = (char *)malloc(strlen((const char *)topic_prefix) + 20);
    sprintf(data->receive_topic, "%s/0.0.0.0", data->topic_pre);
    data->broadcast_topic = (char *)malloc(strlen((const char *)topic_prefix) + 20);
    sprintf(data->broadcast_topic, "%s/255.255.255.255", data->topic_pre);

    netif_add(&data->netif, NULL, NULL, NULL, data, mqtt_if_init, ip_input);
    //	netif_set_default(&data->netif);
    return data;
}

void mqtt_if_del(struct mqtt_if_data *data)
{
    mqtt_if_set_down(data);
    netif_remove(&data->netif);
    free(data->topic_pre);
    free(data->receive_topic);
    free(data->broadcast_topic);
    free(data);
}

void mqtt_if_subscribe(struct mqtt_if_data *data)
{
    esp_mqtt_client_subscribe(data->mqttcl, data->receive_topic, 0);
    esp_mqtt_client_subscribe(data->mqttcl, data->broadcast_topic, 0);

    mqtt_if_set_flag(data, NETIF_FLAG_LINK_UP);

    ESP_LOGI(TAG, "subscribe receive_topic: %s", data->receive_topic);
    ESP_LOGI(TAG, "subscribe broadcast_topic: %s", data->broadcast_topic);
}

void mqtt_if_unsubscribe(struct mqtt_if_data *data)
{
    esp_mqtt_client_unsubscribe(data->mqttcl, data->receive_topic);
    esp_mqtt_client_unsubscribe(data->mqttcl, data->broadcast_topic);

    mqtt_if_clear_flag(data, NETIF_FLAG_LINK_UP);

    ESP_LOGI(TAG, "unsubscribe receive_topic: %s", data->receive_topic);
    ESP_LOGI(TAG, "unsubscribe broadcast_topic: %s", data->broadcast_topic);
}

void mqtt_if_set_password(struct mqtt_if_data *data, char *password)
{
    unsigned char h[crypto_hash_BYTES];

    if (strlen(password) > 0)
    {
        crypto_hash(h, (const unsigned char *)password, strlen(password));
        memcpy(data->key, h, crypto_secretbox_KEYBYTES);
        data->key_set = 1;
    }
    else
    {
        data->key_set = 0;
    }
}

void mqtt_if_set_ipaddr(struct mqtt_if_data *data, uint32_t addr)
{
    ip4_addr_t ipaddr;
    ipaddr.addr = addr;
    netif_set_ipaddr(&data->netif, &ipaddr);
    data->ipaddr = ipaddr;

    sprintf(data->receive_topic, "%s/" IPSTR, (char *)data->topic_pre, IP2STR(&data->ipaddr));
}

void mqtt_if_set_netmask(struct mqtt_if_data *data, uint32_t addr)
{
    ip4_addr_t ipaddr;
    ipaddr.addr = addr;
    netif_set_netmask(&data->netif, &ipaddr);
}

void mqtt_if_set_gw(struct mqtt_if_data *data, uint32_t addr)
{
    ip4_addr_t ipaddr;
    ipaddr.addr = addr;
    netif_set_gw(&data->netif, &ipaddr);
}

void mqtt_if_set_up(struct mqtt_if_data *data)
{
    netif_set_up(&data->netif);
}

void mqtt_if_set_down(struct mqtt_if_data *data)
{
    netif_set_down(&data->netif);
}

void mqtt_if_set_mtu(struct mqtt_if_data *data, int mtu)
{
    data->netif.mtu = mtu;
}

void mqtt_if_set_flag(struct mqtt_if_data *data, int flag)
{
    data->netif.flags |= flag;
}

void mqtt_if_clear_flag(struct mqtt_if_data *data, int flag)
{
    data->netif.flags &= ~flag;
}

static int dns_count;

void mqtt_if_clear_dns(void)
{
    int i;
    for (i = 0; i < DNS_MAX_SERVERS; i++)
        dns_setserver(i, (const ip_addr_t *) IP4_ADDR_ANY);
    dns_count = 0;
}

void mqtt_if_add_dns(uint32_t addr)
{
    ip_addr_t ipaddr;
    ipaddr.u_addr.ip4.addr = addr;
    ipaddr.type = IPADDR_TYPE_V4;
    dns_setserver(dns_count++, (const ip_addr_t *)&ipaddr);
}
