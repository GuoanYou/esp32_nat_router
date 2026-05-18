/*
 * dns_server.c  –  UDP DNS proxy with domain filtering
 *
 * Drop-in replacement for the original esp32_nat_router dns_server.c.
 * Key change: before forwarding a query upstream, dns_filter_check() is
 * called.  Blocked domains get an immediate NXDOMAIN response so the
 * client never contacts the upstream resolver.
 */

#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "dns_filter.h"

static const char *TAG = "dns_server";

#define DNS_PORT        53
#define DNS_BUF_SIZE    512
#define DNS_UPSTREAM_TIMEOUT_MS  3000

/* ------------------------------------------------------------------ */
/* Minimal DNS header                                                   */
/* ------------------------------------------------------------------ */
typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

#define DNS_FLAG_QR      0x8000
#define DNS_FLAG_AA      0x0400
#define DNS_FLAG_RA      0x0080
#define DNS_RCODE_NXDOMAIN 3

/* ------------------------------------------------------------------ */
/* Parse the QNAME from a DNS query                                     */
/* ------------------------------------------------------------------ */
static int parse_qname(const uint8_t *buf, int buf_len, int offset,
                        char *out, int out_len)
{
    int pos = offset;
    int out_pos = 0;
    while (pos < buf_len) {
        uint8_t len = buf[pos++];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) { pos++; break; }   /* pointer – stop */
        if (out_pos + len + 1 >= out_len) return -1;
        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, buf + pos, len);
        out_pos += len;
        pos += len;
    }
    out[out_pos] = '\0';
    return pos;   /* offset after QNAME+QTYPE+QCLASS = pos + 4 */
}

/* ------------------------------------------------------------------ */
/* Build an NXDOMAIN response in-place (modify the query buffer)        */
/* ------------------------------------------------------------------ */
static int build_nxdomain(uint8_t *buf, int query_len)
{
    if (query_len < (int)sizeof(dns_hdr_t)) return -1;
    dns_hdr_t *hdr = (dns_hdr_t *)buf;
    uint16_t flags = ntohs(hdr->flags);
    flags |= DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA;
    flags = (flags & 0xFFF0) | DNS_RCODE_NXDOMAIN;
    hdr->flags   = htons(flags);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;
    return query_len;   /* same length – we just flipped bits */
}

/* ------------------------------------------------------------------ */
/* DNS proxy task                                                        */
/* ------------------------------------------------------------------ */
static void dns_server_task(void *pvParameters)
{
    char *upstream_ip = (char *)pvParameters;   /* e.g. "8.8.8.8" */

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in srv_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(DNS_PORT),
    };
    if (bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        ESP_LOGE(TAG, "Bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    /* Upstream resolver address */
    struct sockaddr_in up_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
    };
    inet_aton(upstream_ip, &up_addr.sin_addr);

    ESP_LOGI(TAG, "DNS proxy started, upstream=%s", upstream_ip);

    uint8_t buf[DNS_BUF_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        int recv_len = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                                (struct sockaddr *)&client_addr, &client_addr_len);
        if (recv_len < (int)sizeof(dns_hdr_t)) continue;

        /* Extract query domain */
        char domain[256] = {0};
        parse_qname(buf, recv_len, sizeof(dns_hdr_t), domain, sizeof(domain));

        /* --- Filter check --- */
        if (!dns_filter_check(domain)) {
            ESP_LOGI(TAG, "BLOCKED: %s", domain);
            int nxlen = build_nxdomain(buf, recv_len);
            if (nxlen > 0) {
                sendto(sock, buf, nxlen, 0,
                       (struct sockaddr *)&client_addr, client_addr_len);
            }
            continue;
        }

        /* Forward to upstream */
        int up_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (up_sock < 0) continue;

        struct timeval tv = { .tv_sec = DNS_UPSTREAM_TIMEOUT_MS / 1000,
                              .tv_usec = (DNS_UPSTREAM_TIMEOUT_MS % 1000) * 1000 };
        setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sendto(up_sock, buf, recv_len, 0,
               (struct sockaddr *)&up_addr, sizeof(up_addr));

        int resp_len = recv(up_sock, buf, sizeof(buf), 0);
        close(up_sock);

        if (resp_len > 0) {
            sendto(sock, buf, resp_len, 0,
                   (struct sockaddr *)&client_addr, client_addr_len);
        }
    }

    close(sock);
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/* Public entry point – call from app_main.c                            */
/* ------------------------------------------------------------------ */
void start_dns_server(const char *upstream_dns)
{
    /* Allocate a persistent copy of the upstream IP string */
    char *ip_copy = strdup(upstream_dns ? upstream_dns : "8.8.8.8");
    xTaskCreate(dns_server_task, "dns_server", 4096, ip_copy, 5, NULL);
}
