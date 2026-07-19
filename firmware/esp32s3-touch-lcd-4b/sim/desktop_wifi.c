// Desktop stand-in for net/wifi.c (#517).
//
// This is the ONE net/ file the mirror does NOT compile for real: wifi.c drives
// esp_wifi/esp_netif/esp_event to JOIN a network, and a laptop is already on
// one. Shimming three ESP-IDF subsystems to reimplement "you have an IP" would
// be pure ceremony — and unlike pairing or chat, nothing about the broker
// contract lives here. Everything downstream (pairing, agent chat) is the real
// firmware code over the real network.
//
// It reports the host's actual outbound IP so the Connection screen shows the
// truth rather than a fixture.
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "app_state.h"
#include "esp_log.h"
#include "wifi.h"

static const char *TAG = "desktop_wifi";

/// The address the OS would use to reach the outside world. A connect() on a UDP
/// socket sets the local endpoint without sending a packet — no DNS, no traffic.
static void outbound_ip(char *out, size_t cap) {
    snprintf(out, cap, "0.0.0.0");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { return; }
    struct sockaddr_in probe = {0};
    probe.sin_family = AF_INET;
    probe.sin_port = htons(53);
    probe.sin_addr.s_addr = inet_addr("1.1.1.1");
    if (connect(s, (struct sockaddr *)&probe, sizeof(probe)) == 0) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        if (getsockname(s, (struct sockaddr *)&local, &len) == 0) {
            inet_ntop(AF_INET, &local.sin_addr, out, (socklen_t)cap);
        }
    }
    close(s);
}

void wifi_start(const char *ssid, const char *password) {
    (void)ssid;
    (void)password;
    char ip[64];
    outbound_ip(ip, sizeof(ip));
    ESP_LOGI(TAG, "desktop network (no join needed) — ip %s", ip);
    app_state_set_ip(ip);
    // Not CONN_AGENT_OK: the agent link is unproven until agent_client_healthz()
    // actually reaches it. Claiming OK here is the kind of fixture-lie this
    // whole change removes.
    app_state_set_conn(CONN_WIFI_OK);
}
