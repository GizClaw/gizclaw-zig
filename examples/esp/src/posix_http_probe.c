#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"

#define READ_BUFFER_SIZE (8 * 1024)
#define PROGRESS_STEP_BYTES (1024 * 1024)

static const char *TAG = "posix_http_probe";

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
} gizclaw_posix_http_result_t;

static int64_t now_us(void)
{
    return esp_timer_get_time();
}

static int fail(gizclaw_posix_http_result_t *out, int rc)
{
    ESP_LOGW(TAG, "failed rc=%d errno=%d", rc, errno);
    if (out != NULL) {
        out->rc = rc;
        out->errno_value = errno;
    }
    return rc;
}

static int send_all(int sock, const char *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send(sock, data + offset, len - offset, 0);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        offset += (size_t)n;
    }
    return 0;
}

static int parse_status_code(const char *header, size_t len)
{
    if (len < 12 || memcmp(header, "HTTP/", 5) != 0) {
        return 0;
    }
    const char *space = memchr(header, ' ', len);
    if (space == NULL || (size_t)(space - header) + 4 > len) {
        return 0;
    }
    int code = 0;
    for (int i = 1; i <= 3; i++) {
        char c = space[i];
        if (c < '0' || c > '9') {
            return 0;
        }
        code = code * 10 + (c - '0');
    }
    return code;
}

static const char *find_header_end(const char *buf, size_t len)
{
    if (len < 4) {
        return NULL;
    }
    for (size_t i = 0; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

int gizclaw_posix_http_download(
    const char *host,
    const uint8_t ip[4],
    uint16_t port,
    const char *path,
    int64_t expected_bytes,
    gizclaw_posix_http_result_t *out)
{
    if (out == NULL || host == NULL || ip == NULL || path == NULL || expected_bytes <= 0) {
        errno = EINVAL;
        return fail(out, -1);
    }

    memset(out, 0, sizeof(*out));
    ESP_LOGI(
        TAG,
        "start host=%s ip=%u.%u.%u.%u port=%u path=%s expected=%lld read_buffer=%u",
        host,
        (unsigned)ip[0],
        (unsigned)ip[1],
        (unsigned)ip[2],
        (unsigned)ip[3],
        (unsigned)port,
        path,
        (long long)expected_bytes,
        (unsigned)READ_BUFFER_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return fail(out, -2);
    }

    struct timeval timeout = {
        .tv_sec = 60,
        .tv_usec = 0,
    };
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(((uint32_t)ip[0] << 24) |
                                 ((uint32_t)ip[1] << 16) |
                                 ((uint32_t)ip[2] << 8) |
                                 ((uint32_t)ip[3]));

    int64_t connect_started = now_us();
    ESP_LOGI(TAG, "connect begin");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return fail(out, -3);
    }
    out->connect_us = now_us() - connect_started;
    ESP_LOGI(TAG, "connect ok connect_us=%lld", (long long)out->connect_us);

    char request[384];
    int request_len = snprintf(
        request,
        sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Range: bytes=0-%lld\r\n"
        "Connection: close\r\n"
        "User-Agent: gizclaw-zig-esp-posix-http-probe\r\n"
        "Accept: */*\r\n"
        "\r\n",
        path,
        host,
        (long long)(expected_bytes - 1));
    if (request_len <= 0 || (size_t)request_len >= sizeof(request)) {
        close(sock);
        errno = EMSGSIZE;
        return fail(out, -4);
    }
    if (send_all(sock, request, (size_t)request_len) != 0) {
        close(sock);
        return fail(out, -5);
    }
    ESP_LOGI(TAG, "request sent bytes=%d", request_len);

    uint8_t *read_buf = (uint8_t *)malloc(READ_BUFFER_SIZE);
    if (read_buf == NULL) {
        close(sock);
        errno = ENOMEM;
        return fail(out, -6);
    }

    char header[4096];
    size_t header_len = 0;
    int header_done = 0;
    int64_t started = now_us();
    int64_t next_progress = PROGRESS_STEP_BYTES;

    while (out->body_bytes < expected_bytes) {
        int64_t recv_started = now_us();
        ssize_t n = recv(sock, read_buf, READ_BUFFER_SIZE, 0);
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
            ESP_LOGW(
                TAG,
                "recv failed calls=%llu body=%lld recv_us=%lld errno=%d",
                (unsigned long long)out->recv_calls,
                (long long)out->body_bytes,
                (long long)recv_us,
                errno);
            free(read_buf);
            close(sock);
            return fail(out, -7);
        }
        if (n == 0) {
            ESP_LOGW(TAG, "recv eof calls=%llu body=%lld", (unsigned long long)out->recv_calls, (long long)out->body_bytes);
            break;
        }

        if (header_done) {
            out->body_bytes += n;
            if (out->body_bytes >= next_progress) {
                ESP_LOGI(
                    TAG,
                    "progress body=%lld calls=%llu last_n=%d max_recv_us=%lld",
                    (long long)out->body_bytes,
                    (unsigned long long)out->recv_calls,
                    (int)n,
                    (long long)out->max_recv_us);
                next_progress += PROGRESS_STEP_BYTES;
            }
            continue;
        }

        size_t prev_header_len = header_len;
        size_t available = sizeof(header) - header_len;
        size_t copy_len = (size_t)n < available ? (size_t)n : available;
        memcpy(header + header_len, read_buf, copy_len);
        header_len += copy_len;

        const char *header_end = find_header_end(header, header_len);
        if (header_end != NULL) {
            header_done = 1;
            out->status_code = parse_status_code(header, header_len);
            size_t body_start = (size_t)(header_end - header) + 4;
            out->body_bytes += (int64_t)(prev_header_len + (size_t)n - body_start);
            ESP_LOGI(
                TAG,
                "header done status=%d header_bytes=%u first_body=%lld calls=%llu",
                out->status_code,
                (unsigned)body_start,
                (long long)out->body_bytes,
                (unsigned long long)out->recv_calls);
        } else if (copy_len < (size_t)n) {
            free(read_buf);
            close(sock);
            errno = EMSGSIZE;
            return fail(out, -8);
        }
    }

    out->duration_us = now_us() - started;
    free(read_buf);
    close(sock);
    ESP_LOGI(
        TAG,
        "done body=%lld duration_us=%lld calls=%llu",
        (long long)out->body_bytes,
        (long long)out->duration_us,
        (unsigned long long)out->recv_calls);

    if (out->body_bytes < expected_bytes) {
        errno = ECONNRESET;
        return fail(out, -9);
    }

    out->rc = 0;
    return 0;
}
