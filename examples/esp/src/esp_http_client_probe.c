#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"

#define HTTP_READ_BUFFER_SIZE (64 * 1024)
#define HTTP_CLIENT_BUFFER_SIZE (32 * 1024)
#define PROGRESS_STEP_BYTES (512 * 1024)

static const char *TAG = "c_http_dl";

typedef struct {
    int rc;
    int status_code;
    int errno_value;
    int64_t body_bytes;
    int64_t duration_us;
    int64_t connect_us;
    uint64_t recv_calls;
    uint64_t slow_recv_calls;
    int64_t max_recv_us;
    size_t max_recv_bytes;
} gizclaw_http_probe_result_t;

static int64_t now_us(void)
{
    return esp_timer_get_time();
}

static int fail(gizclaw_http_probe_result_t *out, int rc, int errno_value)
{
    ESP_LOGW(TAG, "failed rc=%d errno=%d", rc, errno_value);
    if (out != NULL) {
        out->rc = rc;
        out->errno_value = errno_value;
    }
    return rc;
}

static void log_heap(const char *stage)
{
    ESP_LOGI(
        TAG,
        "heap %s free_8bit=%u largest_8bit=%u free_internal=%u largest_internal=%u free_spiram=%u largest_spiram=%u",
        stage,
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
}

int gizclaw_esp_http_client_download(
    const char *url,
    int64_t expected_bytes,
    gizclaw_http_probe_result_t *out)
{
    if (out == NULL || url == NULL || expected_bytes <= 0) {
        errno = EINVAL;
        return fail(out, -1, errno);
    }

    memset(out, 0, sizeof(*out));

    log_heap("before-read-buffer");
    uint8_t *buffer = (uint8_t *)heap_caps_malloc(HTTP_READ_BUFFER_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (buffer == NULL) {
        ESP_LOGW(TAG, "internal malloc %d failed; fallback to psram", HTTP_READ_BUFFER_SIZE);
        buffer = (uint8_t *)heap_caps_malloc(HTTP_READ_BUFFER_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (buffer == NULL) {
            ESP_LOGE(TAG, "read buffer malloc %d failed", HTTP_READ_BUFFER_SIZE);
            log_heap("read-buffer-failed");
            errno = ENOMEM;
            return fail(out, -2, errno);
        }
    }
    log_heap("after-read-buffer");

    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 60000,
        .buffer_size = HTTP_CLIENT_BUFFER_SIZE,
        .buffer_size_tx = 1024,
        .keep_alive_enable = false,
    };

    ESP_LOGI(
        TAG,
        "download open url=%s expected=%" PRId64 " read_buffer=%d client_buffer=%d",
        url,
        expected_bytes,
        HTTP_READ_BUFFER_SIZE,
        HTTP_CLIENT_BUFFER_SIZE);

    log_heap("before-client-init");
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "esp_http_client_init failed");
        log_heap("client-init-failed");
        heap_caps_free(buffer);
        return fail(out, -3, ENOMEM);
    }
    log_heap("after-client-init");

    char range_header[64];
    int range_len = snprintf(
        range_header,
        sizeof(range_header),
        "bytes=0-%lld",
        (long long)(expected_bytes - 1));
    if (range_len <= 0 || (size_t)range_len >= sizeof(range_header)) {
        esp_http_client_cleanup(client);
        heap_caps_free(buffer);
        errno = EMSGSIZE;
        return fail(out, -4, errno);
    }
    (void)esp_http_client_set_header(client, "Range", range_header);
    ESP_LOGI(TAG, "range=%s", range_header);

    int64_t connect_started = now_us();
    esp_err_t err = esp_http_client_open(client, 0);
    out->connect_us = now_us() - connect_started;
    if (err != ESP_OK) {
        int errno_value = esp_http_client_get_errno(client);
        ESP_LOGE(TAG, "http open failed err=%s errno=%d", esp_err_to_name(err), errno_value);
        esp_http_client_cleanup(client);
        heap_caps_free(buffer);
        return fail(out, -5, errno_value);
    }

    int64_t content_length = esp_http_client_fetch_headers(client);
    out->status_code = esp_http_client_get_status_code(client);
    ESP_LOGI(TAG, "http status=%d content_length=%" PRId64, out->status_code, content_length);

    int64_t started = now_us();
    int64_t next_progress = PROGRESS_STEP_BYTES;
    while (true) {
        int64_t recv_started = now_us();
        int n = esp_http_client_read(client, (char *)buffer, HTTP_READ_BUFFER_SIZE);
        int64_t recv_us = now_us() - recv_started;
        out->recv_calls++;
        if (recv_us > out->max_recv_us) {
            out->max_recv_us = recv_us;
            out->max_recv_bytes = n > 0 ? (size_t)n : 0;
        }
        if (recv_us >= 100 * 1000) {
            out->slow_recv_calls++;
        }
        if (n < 0) {
            int errno_value = esp_http_client_get_errno(client);
            ESP_LOGE(TAG, "http read failed read=%d err=%s errno=%d", n, esp_err_to_name(errno_value), errno_value);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            heap_caps_free(buffer);
            return fail(out, -6, errno_value);
        }
        if (n == 0) {
            break;
        }
        out->body_bytes += n;
        if (out->body_bytes >= next_progress) {
            const int64_t now = now_us();
            const int64_t elapsed_us = now - started;
            const double seconds = (double)elapsed_us / 1000000.0;
            const double mbps = seconds > 0.0 ? ((double)out->body_bytes * 8.0) / seconds / 1000000.0 : 0.0;
            ESP_LOGI(
                TAG,
                "progress bytes=%" PRId64 " elapsed_ms=%" PRId64 " mbps=%.3f",
                out->body_bytes,
                elapsed_us / 1000,
                mbps);
            while (next_progress <= out->body_bytes) {
                next_progress += PROGRESS_STEP_BYTES;
            }
        }
    }

    out->duration_us = now_us() - started;
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    heap_caps_free(buffer);
    log_heap("after-cleanup");

    const double seconds = (double)out->duration_us / 1000000.0;
    const double mbps = seconds > 0.0 ? ((double)out->body_bytes * 8.0) / seconds / 1000000.0 : 0.0;
    ESP_LOGI(
        TAG,
        "done bytes=%" PRId64 " expected=%" PRId64 " duration_ms=%" PRId64 " mbps=%.3f recv_calls=%" PRIu64,
        out->body_bytes,
        expected_bytes,
        out->duration_us / 1000,
        mbps,
        out->recv_calls);

    if (out->body_bytes < expected_bytes) {
        errno = ECONNRESET;
        return fail(out, -7, errno);
    }

    out->rc = 0;
    return 0;
}
