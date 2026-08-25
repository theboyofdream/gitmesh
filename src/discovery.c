#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PKT_ANNOUNCE 1
#define PKT_PROBE    2
#define PKT_LEN      (8 + 1 + 2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES)

static int udp_sock(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof enable);
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof enable);
#endif
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof enable);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(GM_DISCO_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        gm_sock_close(fd);
        return -1;
    }
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 200 * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    return fd;
}

static void build_packet(uint8_t *buf, uint8_t kind, const gm_ident *id, uint16_t tcp_port) {
    size_t offset = 0;
    char display_name[GM_NAME_MAX];
    gm_ident_display(id, display_name);
    memcpy(buf + offset, GM_MAGIC, 8);
    offset += 8;
    buf[offset++] = kind;
    buf[offset++] = (uint8_t)(tcp_port & 0xff);
    buf[offset++] = (uint8_t)(tcp_port >> 8);
    memset(buf + offset, 0, GM_NAME_MAX);
    snprintf((char *)buf + offset, GM_NAME_MAX, "%s", display_name);
    offset += GM_NAME_MAX;
    memcpy(buf + offset, id->sign_pk, crypto_sign_PUBLICKEYBYTES);
}

static bool same_pk(const gm_ident *id, const uint8_t *pk) {
    return memcmp(id->sign_pk, pk, crypto_sign_PUBLICKEYBYTES) == 0;
}

uint16_t gm_env_tcp_port(void) {
    const char *env_value = getenv("GITMESH_TCP_PORT");
    if (!env_value || !*env_value) env_value = getenv("GITMESH_PORT");
    if (!env_value || !*env_value) env_value = getenv("GM_TCP_PORT");
    if (env_value && *env_value) {
        long port_value = strtol(env_value, NULL, 10);
        if (port_value > 0 && port_value < 65536) return (uint16_t)port_value;
    }
    return GM_TCP_PORT;
}

void gm_disco_run(const gm_ident *id, uint16_t tcp_port) {
    if (tcp_port == 0) tcp_port = gm_env_tcp_port();
    int fd = udp_sock();
    if (fd < 0) gm_die("discovery: cannot bind UDP %d", GM_DISCO_PORT);
    uint8_t packet[PKT_LEN];
    build_packet(packet, PKT_ANNOUNCE, id, tcp_port);
    struct sockaddr_in broadcast_addr = {0};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(GM_DISCO_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    if (sendto(fd, packet, sizeof packet, 0, (struct sockaddr *)&broadcast_addr, sizeof broadcast_addr) < 0)
        perror("gitmesh: announce");
    gm_sock_close(fd);
}

int gm_disco_collect(const gm_ident *id, gm_peer *out, int max, int ms) {
    int fd = udp_sock();
    if (fd < 0) gm_die("discovery: cannot bind UDP %d", GM_DISCO_PORT);

    uint16_t tcp_port = gm_env_tcp_port();
    uint8_t probe[PKT_LEN];
    build_packet(probe, PKT_PROBE, id, tcp_port);
    struct sockaddr_in broadcast_addr = {0};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(GM_DISCO_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    sendto(fd, probe, sizeof probe, 0, (struct sockaddr *)&broadcast_addr, sizeof broadcast_addr);

    uint8_t announce[PKT_LEN];
    build_packet(announce, PKT_ANNOUNCE, id, tcp_port);

    int64_t deadline = gm_now_ms() + ms;
    int n_peers = 0;
    while (gm_now_ms() < deadline && n_peers < max) {
        uint8_t buf[PKT_LEN];
        struct sockaddr_in sender_addr = {0};
        socklen_t sender_addr_len = sizeof sender_addr;
        ssize_t bytes_read = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);
        if (bytes_read != (ssize_t)sizeof buf) {
            int64_t left = deadline - gm_now_ms();
            if (left > 100) {
                struct timeval timeout = {.tv_sec = (long)left / 1000,
                                          .tv_usec = (long)(left % 1000) * 1000};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
            }
            continue;
        }
        if (memcmp(buf, GM_MAGIC, 8) != 0) continue;
        uint8_t kind = buf[8];
        const uint8_t *pk = buf + 11 + GM_NAME_MAX;
        if (same_pk(id, pk)) continue;

        if (kind == PKT_PROBE) {
            struct sockaddr_in to = {0};
            to.sin_family = AF_INET;
            to.sin_port = htons(GM_DISCO_PORT);
            to.sin_addr = sender_addr.sin_addr;
            sendto(fd, announce, sizeof announce, 0, (struct sockaddr *)&to, sizeof to);
            continue;
        }
        if (kind != PKT_ANNOUNCE) continue;

        bool is_duplicate = false;
        for (int i = 0; i < n_peers; i++)
            if (memcmp(out[i].sign_pk, pk, crypto_sign_PUBLICKEYBYTES) == 0)
                is_duplicate = true;
        if (is_duplicate) continue;

        gm_peer *p = &out[n_peers++];
        inet_ntop(AF_INET, &sender_addr.sin_addr, p->ip, sizeof p->ip);
        p->port = (uint16_t)(buf[9] | buf[10] << 8);
        memcpy(p->name, buf + 11, GM_NAME_MAX);
        p->name[GM_NAME_MAX - 1] = 0;
        memcpy(p->sign_pk, pk, crypto_sign_PUBLICKEYBYTES);
        p->seen_ms = gm_now_ms();
    }
    gm_sock_close(fd);
    return n_peers;
}

int gm_disco_resolve(const gm_ident *id, const char *name, char *ip, uint16_t *port, uint8_t *pk) {
    gm_peer peers[32];
    int peer_count = gm_disco_collect(id, peers, 32, 1500);
    for (int i = 0; i < peer_count; i++) {
        bool is_match = false;
        if (strcasecmp(peers[i].name, name) == 0) is_match = true;
        else {
            char *user_separator = strchr(peers[i].name, '@');
            if (user_separator) {
                size_t prefix_len = (size_t)(user_separator - peers[i].name);
                char prefix[GM_NAME_MAX];
                if (prefix_len < sizeof prefix) {
                    memcpy(prefix, peers[i].name, prefix_len);
                    prefix[prefix_len] = 0;
                    if (strcasecmp(prefix, name) == 0 || strcasecmp(user_separator + 1, name) == 0) is_match = true;
                }
            }
        }
        if (is_match) {
            snprintf(ip, 48, "%s", peers[i].ip);
            *port = peers[i].port ? peers[i].port : gm_env_tcp_port();
            if (pk) memcpy(pk, peers[i].sign_pk, crypto_sign_PUBLICKEYBYTES);
            return 0;
        }
    }
    return -1;
}
