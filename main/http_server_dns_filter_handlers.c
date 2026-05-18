/*
 * http_server_dns_filter_handlers.c
 *
 * 将本文件的内容追加或合并到原项目的 http_server.c 中。
 * 需要在文件顶部 #include 区域添加：
 *   #include "dns_filter.h"
 *
 * 然后在注册 URI 处理函数的地方（httpd_start 之后）添加：
 *   httpd_register_uri_handler(server, &uri_dns_filter_get);
 *   httpd_register_uri_handler(server, &uri_dns_filter_post);
 *   httpd_register_uri_handler(server, &uri_dns_filter_list_post);
 *   httpd_register_uri_handler(server, &uri_dns_filter_list_delete);
 */

#include "esp_http_server.h"
#include "esp_log.h"
#include "dns_filter.h"
#include <string.h>
#include <stdlib.h>

static const char *FTAG = "dns_http";

/* ------------------------------------------------------------------ */
/* Helper: read entire request body                                     */
/* ------------------------------------------------------------------ */
static int read_body(httpd_req_t *req, char *buf, size_t buf_len)
{
    int remaining = req->content_len;
    int received  = 0;
    while (remaining > 0) {
        int ret = httpd_req_recv(req, buf + received,
                                 MIN(remaining, (int)(buf_len - received - 1)));
        if (ret <= 0) return -1;
        received  += ret;
        remaining -= ret;
    }
    buf[received] = '\0';
    return received;
}

/* ------------------------------------------------------------------ */
/* Helper: parse a JSON string value for a given key                   */
/*   {"key":"value"}  →  copies value into out                         */
/* ------------------------------------------------------------------ */
static int json_get_str(const char *json, const char *key, char *out, size_t out_len)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) out[i++] = *p++;
    out[i] = '\0';
    return (int)i;
}

/* ------------------------------------------------------------------ */
/* GET /api/dns_filter  →  full JSON state                             */
/* ------------------------------------------------------------------ */
static esp_err_t dns_filter_get_handler(httpd_req_t *req)
{
    char *buf = malloc(8192);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    dns_filter_to_json(buf, 8192);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, buf);
    free(buf);
    return ESP_OK;
}

static const httpd_uri_t uri_dns_filter_get = {
    .uri     = "/api/dns_filter",
    .method  = HTTP_GET,
    .handler = dns_filter_get_handler,
};

/* ------------------------------------------------------------------ */
/* POST /api/dns_filter  →  set enabled / mode                         */
/*   Body: {"enabled":true,"mode":"blacklist"}                         */
/* ------------------------------------------------------------------ */
static esp_err_t dns_filter_post_handler(httpd_req_t *req)
{
    char body[256];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* enabled */
    if (strstr(body, "\"enabled\":true"))       dns_filter_set_enabled(true);
    else if (strstr(body, "\"enabled\":false"))  dns_filter_set_enabled(false);

    /* mode */
    char mode_str[16];
    if (json_get_str(body, "mode", mode_str, sizeof(mode_str)) >= 0) {
        if (strcmp(mode_str, "whitelist") == 0)
            dns_filter_set_mode(FILTER_MODE_WHITELIST);
        else
            dns_filter_set_mode(FILTER_MODE_BLACKLIST);
    }

    dns_filter_save();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    ESP_LOGI(FTAG, "Filter settings updated: %s", body);
    return ESP_OK;
}

static const httpd_uri_t uri_dns_filter_post = {
    .uri     = "/api/dns_filter",
    .method  = HTTP_POST,
    .handler = dns_filter_post_handler,
};

/* ------------------------------------------------------------------ */
/* POST /api/dns_filter/list                                            */
/*   Body: {"list":"blacklist","domain":"ads.example.com"}             */
/* ------------------------------------------------------------------ */
static esp_err_t dns_filter_list_add_handler(httpd_req_t *req)
{
    char body[256];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char list_type[16], domain[128];
    if (json_get_str(body, "list",   list_type, sizeof(list_type)) < 0 ||
        json_get_str(body, "domain", domain,    sizeof(domain))    < 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing list or domain");
        return ESP_FAIL;
    }

    int ret;
    if (strcmp(list_type, "whitelist") == 0)
        ret = dns_filter_whitelist_add(domain);
    else
        ret = dns_filter_blacklist_add(domain);

    if (ret != 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Add failed (full?)");
        return ESP_FAIL;
    }
    dns_filter_save();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    ESP_LOGI(FTAG, "Added %s → %s", domain, list_type);
    return ESP_OK;
}

static const httpd_uri_t uri_dns_filter_list_post = {
    .uri     = "/api/dns_filter/list",
    .method  = HTTP_POST,
    .handler = dns_filter_list_add_handler,
};

/* ------------------------------------------------------------------ */
/* DELETE /api/dns_filter/list                                          */
/*   Body: {"list":"blacklist","domain":"ads.example.com"}             */
/* ------------------------------------------------------------------ */
static esp_err_t dns_filter_list_del_handler(httpd_req_t *req)
{
    char body[256];
    if (read_body(req, body, sizeof(body)) < 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char list_type[16], domain[128];
    if (json_get_str(body, "list",   list_type, sizeof(list_type)) < 0 ||
        json_get_str(body, "domain", domain,    sizeof(domain))    < 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing list or domain");
        return ESP_FAIL;
    }

    int ret;
    if (strcmp(list_type, "whitelist") == 0)
        ret = dns_filter_whitelist_remove(domain);
    else
        ret = dns_filter_blacklist_remove(domain);

    if (ret != 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Domain not found");
        return ESP_FAIL;
    }
    dns_filter_save();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    ESP_LOGI(FTAG, "Removed %s from %s", domain, list_type);
    return ESP_OK;
}

static const httpd_uri_t uri_dns_filter_list_delete = {
    .uri     = "/api/dns_filter/list",
    .method  = HTTP_DELETE,
    .handler = dns_filter_list_del_handler,
};

/* ------------------------------------------------------------------ */
/* Call this from your existing start_webserver() / http_server_init() */
/* ------------------------------------------------------------------ */
void register_dns_filter_handlers(httpd_handle_t server)
{
    httpd_register_uri_handler(server, &uri_dns_filter_get);
    httpd_register_uri_handler(server, &uri_dns_filter_post);
    httpd_register_uri_handler(server, &uri_dns_filter_list_post);
    httpd_register_uri_handler(server, &uri_dns_filter_list_delete);
    ESP_LOGI(FTAG, "DNS filter HTTP handlers registered");
}
