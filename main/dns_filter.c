/*
 * dns_filter.c
 * Domain-name filtering for esp32_nat_router (blacklist / whitelist mode).
 * Persisted to NVS so settings survive reboot.
 */

#include "dns_filter.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>

static const char *TAG = "dns_filter";

#define NVS_NS          "dns_flt"
#define NVS_KEY_ENABLED "enabled"
#define NVS_KEY_MODE    "mode"
#define NVS_KEY_BL      "blacklist"
#define NVS_KEY_WL      "whitelist"

/* ------------------------------------------------------------------ */
/* Internal state                                                       */
/* ------------------------------------------------------------------ */
static bool              s_enabled   = false;
static dns_filter_mode_t s_mode      = FILTER_MODE_BLACKLIST;

static char s_blacklist[DNS_FILTER_MAX_DOMAINS][DNS_FILTER_MAX_DOMAIN_LEN];
static int  s_bl_count = 0;

static char s_whitelist[DNS_FILTER_MAX_DOMAINS][DNS_FILTER_MAX_DOMAIN_LEN];
static int  s_wl_count = 0;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/** Lowercase and strip a trailing dot from domain */
static void normalise(const char *src, char *dst, size_t dst_len)
{
    size_t n = strlen(src);
    if (n > 0 && src[n - 1] == '.') n--;          /* strip trailing dot */
    if (n >= dst_len) n = dst_len - 1;
    for (size_t i = 0; i < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[n] = '\0';
}

/** Returns true if domain matches pattern (or is a subdomain of pattern).
 *  pattern "example.com" matches "example.com" and "sub.example.com".
 */
static bool domain_matches(const char *domain, const char *pattern)
{
    size_t dl = strlen(domain);
    size_t pl = strlen(pattern);
    if (dl < pl) return false;
    if (strcasecmp(domain + dl - pl, pattern) != 0) return false;
    /* exact match or subdomain */
    if (dl == pl) return true;
    return domain[dl - pl - 1] == '.';
}

/** Serialise a list of domains into a single NVS blob separated by '\n' */
static void list_to_blob(char (*list)[DNS_FILTER_MAX_DOMAIN_LEN], int count,
                          char *out, size_t out_len)
{
    size_t pos = 0;
    for (int i = 0; i < count && pos < out_len - 1; i++) {
        size_t n = strlcpy(out + pos, list[i], out_len - pos);
        pos += n;
        if (pos < out_len - 1) out[pos++] = '\n';
    }
    out[pos] = '\0';
}

/** Deserialise a blob back into a domain list */
static int blob_to_list(const char *blob, char (*list)[DNS_FILTER_MAX_DOMAIN_LEN],
                         int max_count)
{
    int count = 0;
    const char *p = blob;
    while (*p && count < max_count) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && len < DNS_FILTER_MAX_DOMAIN_LEN) {
            memcpy(list[count], p, len);
            list[count][len] = '\0';
            count++;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Public API – init / check                                            */
/* ------------------------------------------------------------------ */

void dns_filter_init(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "No saved filter config – using defaults");
        return;
    }

    uint8_t v8;
    if (nvs_get_u8(h, NVS_KEY_ENABLED, &v8) == ESP_OK) s_enabled = (bool)v8;
    if (nvs_get_u8(h, NVS_KEY_MODE,    &v8) == ESP_OK) s_mode    = (dns_filter_mode_t)v8;

    /* Load blacklist blob */
    size_t blob_size = 0;
    if (nvs_get_str(h, NVS_KEY_BL, NULL, &blob_size) == ESP_OK && blob_size > 1) {
        char *blob = malloc(blob_size);
        if (blob && nvs_get_str(h, NVS_KEY_BL, blob, &blob_size) == ESP_OK) {
            s_bl_count = blob_to_list(blob, s_blacklist, DNS_FILTER_MAX_DOMAINS);
        }
        free(blob);
    }

    /* Load whitelist blob */
    blob_size = 0;
    if (nvs_get_str(h, NVS_KEY_WL, NULL, &blob_size) == ESP_OK && blob_size > 1) {
        char *blob = malloc(blob_size);
        if (blob && nvs_get_str(h, NVS_KEY_WL, blob, &blob_size) == ESP_OK) {
            s_wl_count = blob_to_list(blob, s_whitelist, DNS_FILTER_MAX_DOMAINS);
        }
        free(blob);
    }

    nvs_close(h);
    ESP_LOGI(TAG, "Loaded: enabled=%d mode=%d bl=%d wl=%d",
             s_enabled, s_mode, s_bl_count, s_wl_count);
}

bool dns_filter_check(const char *domain)
{
    if (!s_enabled || !domain) return true;   /* filter off → always allow */

    char norm[DNS_FILTER_MAX_DOMAIN_LEN];
    normalise(domain, norm, sizeof(norm));

    if (s_mode == FILTER_MODE_BLACKLIST) {
        /* block if in blacklist */
        for (int i = 0; i < s_bl_count; i++) {
            if (domain_matches(norm, s_blacklist[i])) {
                ESP_LOGD(TAG, "BLOCKED (blacklist) %s", norm);
                return false;
            }
        }
        return true;
    } else {
        /* whitelist mode: only allow if in whitelist */
        for (int i = 0; i < s_wl_count; i++) {
            if (domain_matches(norm, s_whitelist[i])) {
                return true;
            }
        }
        ESP_LOGD(TAG, "BLOCKED (not in whitelist) %s", norm);
        return false;
    }
}

/* ------------------------------------------------------------------ */
/* Control getters / setters                                            */
/* ------------------------------------------------------------------ */

void dns_filter_set_enabled(bool enabled) { s_enabled = enabled; }
bool dns_filter_is_enabled(void)          { return s_enabled; }
void dns_filter_set_mode(dns_filter_mode_t mode) { s_mode = mode; }
dns_filter_mode_t dns_filter_get_mode(void)      { return s_mode; }

/* ------------------------------------------------------------------ */
/* Blacklist management                                                 */
/* ------------------------------------------------------------------ */

int dns_filter_blacklist_add(const char *domain)
{
    if (!domain || s_bl_count >= DNS_FILTER_MAX_DOMAINS) return -1;
    char norm[DNS_FILTER_MAX_DOMAIN_LEN];
    normalise(domain, norm, sizeof(norm));
    for (int i = 0; i < s_bl_count; i++) {
        if (strcasecmp(s_blacklist[i], norm) == 0) return 0; /* already exists */
    }
    strlcpy(s_blacklist[s_bl_count++], norm, DNS_FILTER_MAX_DOMAIN_LEN);
    return 0;
}

int dns_filter_blacklist_remove(const char *domain)
{
    char norm[DNS_FILTER_MAX_DOMAIN_LEN];
    normalise(domain, norm, sizeof(norm));
    for (int i = 0; i < s_bl_count; i++) {
        if (strcasecmp(s_blacklist[i], norm) == 0) {
            memmove(s_blacklist[i], s_blacklist[i + 1],
                    (s_bl_count - i - 1) * DNS_FILTER_MAX_DOMAIN_LEN);
            s_bl_count--;
            return 0;
        }
    }
    return -1;
}

int         dns_filter_blacklist_count(void)        { return s_bl_count; }
const char *dns_filter_blacklist_get(int i)         { return (i >= 0 && i < s_bl_count) ? s_blacklist[i] : NULL; }
void        dns_filter_blacklist_clear(void)        { s_bl_count = 0; }

/* ------------------------------------------------------------------ */
/* Whitelist management                                                 */
/* ------------------------------------------------------------------ */

int dns_filter_whitelist_add(const char *domain)
{
    if (!domain || s_wl_count >= DNS_FILTER_MAX_DOMAINS) return -1;
    char norm[DNS_FILTER_MAX_DOMAIN_LEN];
    normalise(domain, norm, sizeof(norm));
    for (int i = 0; i < s_wl_count; i++) {
        if (strcasecmp(s_whitelist[i], norm) == 0) return 0;
    }
    strlcpy(s_whitelist[s_wl_count++], norm, DNS_FILTER_MAX_DOMAIN_LEN);
    return 0;
}

int dns_filter_whitelist_remove(const char *domain)
{
    char norm[DNS_FILTER_MAX_DOMAIN_LEN];
    normalise(domain, norm, sizeof(norm));
    for (int i = 0; i < s_wl_count; i++) {
        if (strcasecmp(s_whitelist[i], norm) == 0) {
            memmove(s_whitelist[i], s_whitelist[i + 1],
                    (s_wl_count - i - 1) * DNS_FILTER_MAX_DOMAIN_LEN);
            s_wl_count--;
            return 0;
        }
    }
    return -1;
}

int         dns_filter_whitelist_count(void)        { return s_wl_count; }
const char *dns_filter_whitelist_get(int i)         { return (i >= 0 && i < s_wl_count) ? s_whitelist[i] : NULL; }
void        dns_filter_whitelist_clear(void)        { s_wl_count = 0; }

/* ------------------------------------------------------------------ */
/* Persist to NVS                                                       */
/* ------------------------------------------------------------------ */

void dns_filter_save(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for write");
        return;
    }

    nvs_set_u8(h, NVS_KEY_ENABLED, (uint8_t)s_enabled);
    nvs_set_u8(h, NVS_KEY_MODE,    (uint8_t)s_mode);

    /* Serialize lists */
    size_t buf_size = DNS_FILTER_MAX_DOMAINS * DNS_FILTER_MAX_DOMAIN_LEN;
    char *blob = malloc(buf_size);
    if (blob) {
        list_to_blob(s_blacklist, s_bl_count, blob, buf_size);
        nvs_set_str(h, NVS_KEY_BL, blob);
        list_to_blob(s_whitelist, s_wl_count, blob, buf_size);
        nvs_set_str(h, NVS_KEY_WL, blob);
        free(blob);
    }

    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Filter config saved");
}

/* ------------------------------------------------------------------ */
/* JSON serialisation                                                   */
/* ------------------------------------------------------------------ */

int dns_filter_to_json(char *buf, size_t buf_len)
{
    int pos = 0;

    pos += snprintf(buf + pos, buf_len - pos,
                    "{\"enabled\":%s,\"mode\":\"%s\",\"blacklist\":[",
                    s_enabled ? "true" : "false",
                    s_mode == FILTER_MODE_BLACKLIST ? "blacklist" : "whitelist");

    for (int i = 0; i < s_bl_count && pos < (int)buf_len - 4; i++) {
        if (i) buf[pos++] = ',';
        pos += snprintf(buf + pos, buf_len - pos, "\"%s\"", s_blacklist[i]);
    }

    pos += snprintf(buf + pos, buf_len - pos, "],\"whitelist\":[");

    for (int i = 0; i < s_wl_count && pos < (int)buf_len - 4; i++) {
        if (i) buf[pos++] = ',';
        pos += snprintf(buf + pos, buf_len - pos, "\"%s\"", s_whitelist[i]);
    }

    pos += snprintf(buf + pos, buf_len - pos, "]}");
    return pos;
}
