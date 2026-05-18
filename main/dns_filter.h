#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_FILTER_MAX_DOMAINS   200
#define DNS_FILTER_MAX_DOMAIN_LEN 128

typedef enum {
    FILTER_MODE_BLACKLIST = 0,
    FILTER_MODE_WHITELIST = 1,
} dns_filter_mode_t;

/**
 * @brief Initialize DNS filter module (loads config from NVS)
 */
void dns_filter_init(void);

/**
 * @brief Check if a domain should be allowed
 * @return true = allow, false = block
 */
bool dns_filter_check(const char *domain);

/* -------- Control -------- */
void dns_filter_set_enabled(bool enabled);
bool dns_filter_is_enabled(void);
void dns_filter_set_mode(dns_filter_mode_t mode);
dns_filter_mode_t dns_filter_get_mode(void);

/* -------- Blacklist -------- */
int  dns_filter_blacklist_add(const char *domain);
int  dns_filter_blacklist_remove(const char *domain);
int  dns_filter_blacklist_count(void);
const char *dns_filter_blacklist_get(int index);
void dns_filter_blacklist_clear(void);

/* -------- Whitelist -------- */
int  dns_filter_whitelist_add(const char *domain);
int  dns_filter_whitelist_remove(const char *domain);
int  dns_filter_whitelist_count(void);
const char *dns_filter_whitelist_get(int index);
void dns_filter_whitelist_clear(void);

/* -------- Persist -------- */
void dns_filter_save(void);

/* -------- JSON helpers (for HTTP API) -------- */
/** Fill buf with JSON representation of current filter state */
int dns_filter_to_json(char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
