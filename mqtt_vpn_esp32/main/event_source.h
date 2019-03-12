#ifndef EVENT_SOURCE_H_
#define EVENT_SOURCE_H_

#include "esp_event.h"
#include "esp_event_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

ESP_EVENT_DECLARE_BASE(MQTTVPN_EVENTS);

enum {
    PACKET_RECEIVED_EVENT,
    PACKET_SEND_EVENT,
};

#ifdef __cplusplus
}
#endif

#endif // #ifndef EVENT_SOURCE_H_