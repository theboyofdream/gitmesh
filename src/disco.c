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
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(GM_DISCO_PORT);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    struct timeval tv = {.tv_sec = 0, .tv_usec = 200 * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static void build_packet(uint8_t *buf, uint8_t kind, const gm_ident *id, uint16_t tcp_port) {
    size_t off = 0;
    memcpy(buf + off, GM_MAGIC, 8);
    off += 8;
    buf[off++] = kind;
    buf[off++] = (uint8_t)(tcp_port & 0xff);
    buf[off++] = (uint8_t)(tcp_port >> 8);
    memset(buf + off, 0, GM_NAME_MAX);
    snprintf((char *)buf + off, GM_NAME_MAX, "%s", id->name);
    off += GM_NAME_MAX;
    memcpy(buf + off, id->sign_pk, crypto_sign_PUBLICKEYBYTES);
}

static bool same_pk(const gm_ident *id, const uint8_t *pk) {
    return memcmp(id->sign_pk, pk, crypto_sign_PUBLICKEYBYTES) == 0;
}

void gm_disco_run(const gm_ident *id, uint16_t tcp_port) {
    int fd = udp_sock();
    if (fd < 0) gm_die("discovery: cannot bind UDP %d", GM_DISCO_PORT);
    uint8_t pkt[PKT_LEN];
    build_packet(pkt, PKT_ANNOUNCE, id, tcp_port);
    struct sockaddr_in bc = {0};
    bc.sin_family = AF_INET;
    bc.sin_port = htons(GM_DISCO_PORT);
    bc.sin_addr.s_addr = inet_addr("255.255.255.255");
    if (sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&bc, sizeof bc) < 0)
        perror("gitmesh: announce");
    close(fd);
}

int gm_disco_collect(const gm_ident *id, gm_peer *out, int max, int ms) {
    int fd = udp_sock();
    if (fd < 0) gm_die("discovery: cannot bind UDP %d", GM_DISCO_PORT);

    uint8_t probe[PKT_LEN];
    build_packet(probe, PKT_PROBE, id, GM_TCP_PORT);
    struct sockaddr_in bc = {0};
    bc.sin_family = AF_INET;
    bc.sin_port = htons(GM_DISCO_PORT);
    bc.sin_addr.s_addr = inet_addr("255.255.255.255");
    sendto(fd, probe, sizeof probe, 0, (struct sockaddr *)&bc, sizeof bc);

    uint8_t announce[PKT_LEN];
    build_packet(announce, PKT_ANNOUNCE, id, GM_TCP_PORT);

    int64_t deadline = gm_now_ms() + ms;
    int n_peers = 0;
    while (gm_now_ms() < deadline && n_peers < max) {
        uint8_t buf[PKT_LEN];
        struct sockaddr_in from = {0};
        socklen_t flen = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
        if (r != (ssize_t)sizeof buf) {
            int64_t left = deadline - gm_now_ms();
            if (left > 100) {
                struct timeval tv = {.tv_sec = (long)left / 1000,
                                     .tv_usec = (long)(left % 1000) * 1000};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
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
            to.sin_addr = from.sin_addr;
            sendto(fd, announce, sizeof announce, 0, (struct sockaddr *)&to, sizeof to);
            continue;
        }
        if (kind != PKT_ANNOUNCE) continue;

        bool dup = false;
        for (int i = 0; i < n_peers; i++)
            if (memcmp(out[i].sign_pk, pk, crypto_sign_PUBLICKEYBYTES) == 0)
                dup = true;
        if (dup) continue;

        gm_peer *p = &out[n_peers++];
        inet_ntop(AF_INET, &from.sin_addr, p->ip, sizeof p->ip);
        p->port = (uint16_t)(buf[9] | buf[10] << 8);
        memcpy(p->name, buf + 11, GM_NAME_MAX);
        p->name[GM_NAME_MAX - 1] = 0;
        memcpy(p->sign_pk, pk, crypto_sign_PUBLICKEYBYTES);
        p->seen_ms = gm_now_ms();
    }
    close(fd);
    return n_peers;
}

int gm_disco_resolve(const gm_ident *id, const char *name, char *ip, uint16_t *port, uint8_t *pk) {
    gm_peer peers[32];
    int n = gm_disco_collect(id, peers, 32, 1500);
    for (int i = 0; i < n; i++) {
        if (strcasecmp(peers[i].name, name) == 0) {
            snprintf(ip, 48, "%s", peers[i].ip);
            *port = peers[i].port ? peers[i].port : GM_TCP_PORT;
            memcpy(pk, peers[i].sign_pk, crypto_sign_PUBLICKEYBYTES);
            return 0;
        }
    }
    return -1;
}
