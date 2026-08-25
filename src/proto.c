#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum {
    HP_HELLO = 30,
    HP_CHALLENGE = 31,
    HP_AUTH = 32,
};

struct gm_sess {
    int fd;
    uint8_t tx_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    uint8_t rx_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_state tx_st, rx_st;
    bool tx_on, rx_on;
    bool server;
    char peer_name[GM_NAME_MAX];
    uint8_t peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
};

static int raw_send(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int raw_recv(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int gm_send_msg(gm_sess *s, uint8_t type, const void *payload, uint32_t len) {
    size_t plen = 5u + len;
    if (len > GM_FRAME_MAX || plen > GM_FRAME_MAX) return -1;
    uint8_t *pt = gm_xmalloc(plen);
    pt[0] = type;
    memcpy(pt + 1, &len, 4);
    if (len && payload) memcpy(pt + 5, payload, len);

    uint8_t *ct = gm_xmalloc(plen + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long ctlen = 0;
    if (crypto_secretstream_xchacha20poly1305_push(
            &s->tx_st, ct, &ctlen, pt, plen, NULL, 0, 0) != 0) {
        free(pt);
        free(ct);
        return -1;
    }
    free(pt);
    uint32_t netlen = (uint32_t)ctlen;
    int rc = raw_send(s->fd, &netlen, 4) || raw_send(s->fd, ct, ctlen);
    free(ct);
    return rc ? -1 : 0;
}

int gm_recv_msg(gm_sess *s, uint8_t *type, uint8_t **payload, uint32_t *len) {
    uint32_t netlen = 0;
    if (raw_recv(s->fd, &netlen, 4) != 0) return -1;
    if (netlen == 0 || netlen > GM_FRAME_MAX + 64) return -1;
    uint8_t *ct = gm_xmalloc(netlen);
    if (raw_recv(s->fd, ct, netlen) != 0) {
        free(ct);
        return -1;
    }
    uint8_t *pt = gm_xmalloc(netlen);
    unsigned long long plen = 0;
    int rc = crypto_secretstream_xchacha20poly1305_pull(
        &s->rx_st, pt, &plen, NULL, ct, netlen, NULL, 0);
    free(ct);
    if (rc != 0 || plen < 5) {
        free(pt);
        return -1;
    }
    uint32_t inner;
    memcpy(&inner, pt + 1, 4);
    if (inner != plen - 5) {
        free(pt);
        return -1;
    }
    *type = pt[0];
    *len = inner;
    if (inner == 0) {
        *payload = NULL;
        free(pt);
    } else {
        memmove(pt, pt + 5, inner);
        *payload = pt;
    }
    return 0;
}

static int send_hello(gm_sess *s, const gm_ident *id) {
    uint8_t h[2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES];
    uint16_t ver = (uint16_t)GM_PROTO_VERSION;
    memcpy(h, &ver, 2);
    memset(h + 2, 0, GM_NAME_MAX);
    snprintf((char *)h + 2, GM_NAME_MAX, "%s", id->name);
    memcpy(h + 2 + GM_NAME_MAX, id->sign_pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(h + 2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES, id->kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    return raw_send(s->fd, h, sizeof h);
}

static int recv_hello(gm_sess *s, uint8_t *peer_kx_pk) {
    uint8_t h[2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES];
    if (raw_recv(s->fd, h, sizeof h) != 0) return -1;
    uint16_t ver;
    memcpy(&ver, h, 2);
    if (ver != GM_PROTO_VERSION) return -1;
    memcpy(s->peer_name, h + 2, GM_NAME_MAX);
    s->peer_name[GM_NAME_MAX - 1] = 0;
    memcpy(s->peer_sign_pk, h + 2 + GM_NAME_MAX, crypto_sign_PUBLICKEYBYTES);
    memcpy(peer_kx_pk, h + 2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES,
           crypto_kx_PUBLICKEYBYTES);
    return 0;
}

static int start_crypto(gm_sess *s) {
    uint8_t hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&s->tx_st, hdr, s->tx_key);
    if (raw_send(s->fd, hdr, sizeof hdr) != 0) return -1;
    if (raw_recv(s->fd, hdr, sizeof hdr) != 0) return -1;
    crypto_secretstream_xchacha20poly1305_init_pull(&s->rx_st, hdr, s->rx_key);
    s->tx_on = s->rx_on = true;
    return 0;
}

gm_sess *gm_connect(const char *ip, uint16_t port) {
    gm_ident id;
    if (gm_ident_load(&id) != 0) gm_die("identity load failed");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) gm_die("socket: %s", strerror(errno));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
        gm_die("bad address %s", ip);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0)
        gm_die("connect %s:%u failed (%s)", ip, port, strerror(errno));

    gm_sess *s = calloc(1, sizeof *s);
    s->fd = fd;
    s->server = false;

    uint8_t peer_kx_pk[crypto_kx_PUBLICKEYBYTES];
    if (send_hello(s, &id) != 0 || recv_hello(s, peer_kx_pk) != 0)
        gm_die("handshake: protocol mismatch");
    if (crypto_kx_client_session_keys(s->rx_key, s->tx_key, id.kx_pk, id.kx_sk,
                                      peer_kx_pk) != 0)
        gm_die("key exchange failed");
    if (start_crypto(s) != 0) gm_die("crypto setup failed");

    uint8_t *chal = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    if (gm_recv_msg(s, &type, &chal, &len) != 0 || type != HP_CHALLENGE ||
        len != 32) {
        gm_close(s);
        gm_die("auth: no challenge");
    }
    uint8_t transcript[3 + 32 + 2 * crypto_kx_PUBLICKEYBYTES];
    memcpy(transcript, "GM1", 3);
    memcpy(transcript + 3, chal, 32);
    memcpy(transcript + 35, peer_kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(transcript + 35 + crypto_kx_PUBLICKEYBYTES, id.kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    free(chal);

    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, transcript, sizeof transcript, id.sign_sk);
    if (gm_send_msg(s, HP_AUTH, sig, sizeof sig) != 0) {
        gm_close(s);
        gm_die("auth: send failed");
    }

    uint8_t *srv_sig = NULL;
    if (gm_recv_msg(s, &type, &srv_sig, &len) != 0 ||
        (type != HP_AUTH && type != GM_ERR)) {
        gm_close(s);
        gm_die("auth: no reply");
    }
    if (type == GM_ERR) {
        gm_close(s);
        gm_die("auth rejected by peer");
    }
    if (len != crypto_sign_BYTES ||
        crypto_sign_verify_detached(srv_sig, transcript, sizeof transcript,
                                    s->peer_sign_pk) != 0) {
        gm_close(s);
        gm_die("auth: peer signature invalid");
    }
    free(srv_sig);
    return s;
}

gm_sess *gm_serve(int fd) {
    gm_ident id;
    if (gm_ident_load(&id) != 0) gm_die("identity load failed");

    gm_sess *s = calloc(1, sizeof *s);
    s->fd = fd;
    s->server = true;

    uint8_t peer_kx_pk[crypto_kx_PUBLICKEYBYTES];
    if (recv_hello(s, peer_kx_pk) != 0 || send_hello(s, &id) != 0) {
        gm_close(s);
        return NULL;
    }
    if (crypto_kx_server_session_keys(s->rx_key, s->tx_key, id.kx_pk, id.kx_sk,
                                      peer_kx_pk) != 0) {
        gm_close(s);
        return NULL;
    }
    if (start_crypto(s) != 0) {
        gm_close(s);
        return NULL;
    }

    uint8_t chal[32];
    randombytes_buf(chal, sizeof chal);
    if (gm_send_msg(s, HP_CHALLENGE, chal, sizeof chal) != 0) {
        gm_close(s);
        return NULL;
    }

    uint8_t *sig = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    if (gm_recv_msg(s, &type, &sig, &len) != 0 || type != HP_AUTH ||
        len != crypto_sign_BYTES) {
        gm_close(s);
        return NULL;
    }
    uint8_t transcript[3 + 32 + 2 * crypto_kx_PUBLICKEYBYTES];
    memcpy(transcript, "GM1", 3);
    memcpy(transcript + 3, chal, 32);
    memcpy(transcript + 35, id.kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(transcript + 35 + crypto_kx_PUBLICKEYBYTES, peer_kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    int ok = crypto_sign_verify_detached(sig, transcript, sizeof transcript,
                                         s->peer_sign_pk) == 0;
    free(sig);
    if (!ok) {
        gm_send_msg(s, GM_ERR, "bad signature", 13);
        gm_close(s);
        return NULL;
    }
    return s;
}

int gm_listen(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(GM_TCP_PORT);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 ||
        listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

const char *gm_sess_peer_name(gm_sess *s) { return s->peer_name; }

const uint8_t *gm_sess_peer_pk(gm_sess *s) { return s->peer_sign_pk; }

void gm_close(gm_sess *s) {
    if (!s) return;
    gm_sock_close(s->fd);
    sodium_memzero(s, sizeof *s);
    free(s);
}
