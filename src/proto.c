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
    crypto_secretstream_xchacha20poly1305_state tx_st;
    crypto_secretstream_xchacha20poly1305_state rx_st;
    bool tx_on;
    bool rx_on;
    bool server;
    char peer_name[GM_NAME_MAX];
    uint8_t peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
};

static int raw_send(int fd, const void *buf, size_t n) {
    const uint8_t *cursor = buf;
    while (n > 0) {
        ssize_t bytes_sent = send(fd, cursor, n, MSG_NOSIGNAL);
        if (bytes_sent <= 0) return -1;
        cursor += bytes_sent;
        n -= (size_t)bytes_sent;
    }
    return 0;
}

static int raw_recv(int fd, void *buf, size_t n) {
    uint8_t *cursor = buf;
    while (n > 0) {
        ssize_t bytes_read = recv(fd, cursor, n, 0);
        if (bytes_read <= 0) return -1;
        cursor += bytes_read;
        n -= (size_t)bytes_read;
    }
    return 0;
}

int gm_send_msg(gm_sess *session, uint8_t type, const void *payload, uint32_t len) {
    size_t frame_len = 5u + len;
    if (len > GM_FRAME_MAX || frame_len > GM_FRAME_MAX) return -1;
    uint8_t *plaintext = gm_xmalloc(frame_len);
    plaintext[0] = type;
    memcpy(plaintext + 1, &len, 4);
    if (len && payload) memcpy(plaintext + 5, payload, len);

    uint8_t *ciphertext = gm_xmalloc(frame_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long cipher_len = 0;
    if (crypto_secretstream_xchacha20poly1305_push(
            &session->tx_st, ciphertext, &cipher_len, plaintext, frame_len, NULL, 0, 0) != 0) {
        free(plaintext);
        free(ciphertext);
        return -1;
    }
    free(plaintext);
    uint32_t wire_len = (uint32_t)cipher_len;
    int result = raw_send(session->fd, &wire_len, 4) || raw_send(session->fd, ciphertext, cipher_len);
    free(ciphertext);
    return result ? -1 : 0;
}

int gm_recv_msg(gm_sess *session, uint8_t *type, uint8_t **payload, uint32_t *len) {
    uint32_t wire_len = 0;
    if (raw_recv(session->fd, &wire_len, 4) != 0) return -1;
    if (wire_len == 0 || wire_len > GM_FRAME_MAX + 64) return -1;
    uint8_t *ciphertext = gm_xmalloc(wire_len);
    if (raw_recv(session->fd, ciphertext, wire_len) != 0) {
        free(ciphertext);
        return -1;
    }
    uint8_t *plaintext = gm_xmalloc(wire_len);
    unsigned long long plain_len = 0;
    int rc = crypto_secretstream_xchacha20poly1305_pull(
        &session->rx_st, plaintext, &plain_len, NULL, ciphertext, wire_len, NULL, 0);
    free(ciphertext);
    if (rc != 0 || plain_len < 5) {
        free(plaintext);
        return -1;
    }
    uint32_t inner_len;
    memcpy(&inner_len, plaintext + 1, 4);
    if (inner_len != plain_len - 5) {
        free(plaintext);
        return -1;
    }
    *type = plaintext[0];
    *len = inner_len;
    if (inner_len == 0) {
        *payload = NULL;
        free(plaintext);
    } else {
        memmove(plaintext, plaintext + 5, inner_len);
        *payload = plaintext;
    }
    return 0;
}

static int send_hello(gm_sess *session, const gm_ident *id) {
    uint8_t hello_frame[2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES];
    uint16_t protocol_version = (uint16_t)GM_PROTO_VERSION;
    char display[GM_NAME_MAX];
    gm_ident_display(id, display);
    memcpy(hello_frame, &protocol_version, 2);
    memset(hello_frame + 2, 0, GM_NAME_MAX);
    snprintf((char *)hello_frame + 2, GM_NAME_MAX, "%s", display);
    memcpy(hello_frame + 2 + GM_NAME_MAX, id->sign_pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(hello_frame + 2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES, id->kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    return raw_send(session->fd, hello_frame, sizeof hello_frame);
}

static int recv_hello(gm_sess *session, uint8_t *peer_kx_pk) {
    uint8_t hello_frame[2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES];
    if (raw_recv(session->fd, hello_frame, sizeof hello_frame) != 0) return -1;
    uint16_t protocol_version;
    memcpy(&protocol_version, hello_frame, 2);
    if (protocol_version != GM_PROTO_VERSION) return -1;
    memcpy(session->peer_name, hello_frame + 2, GM_NAME_MAX);
    session->peer_name[GM_NAME_MAX - 1] = 0;
    memcpy(session->peer_sign_pk, hello_frame + 2 + GM_NAME_MAX, crypto_sign_PUBLICKEYBYTES);
    memcpy(peer_kx_pk, hello_frame + 2 + GM_NAME_MAX + crypto_sign_PUBLICKEYBYTES,
           crypto_kx_PUBLICKEYBYTES);
    return 0;
}

static int start_crypto(gm_sess *session) {
    uint8_t stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&session->tx_st, stream_header, session->tx_key);
    if (raw_send(session->fd, stream_header, sizeof stream_header) != 0) return -1;
    if (raw_recv(session->fd, stream_header, sizeof stream_header) != 0) return -1;
    crypto_secretstream_xchacha20poly1305_init_pull(&session->rx_st, stream_header, session->rx_key);
    session->tx_on = session->rx_on = true;
    return 0;
}

gm_sess *gm_connect(const char *ip, uint16_t port) {
    gm_ident id;
    if (gm_ident_load(&id) != 0) gm_die("identity load failed");
    gm_sock_init();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) gm_die("socket: %s", strerror(errno));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
        gm_die("bad address %s", ip);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
        gm_die("connect %s:%u failed (%s)", ip, port, strerror(errno));

    gm_sess *session = calloc(1, sizeof *session);
    session->fd = fd;
    session->server = false;

    uint8_t peer_kx_pk[crypto_kx_PUBLICKEYBYTES];
    if (send_hello(session, &id) != 0 || recv_hello(session, peer_kx_pk) != 0)
        gm_die("handshake: protocol mismatch");
    if (crypto_kx_client_session_keys(session->rx_key, session->tx_key, id.kx_pk, id.kx_sk,
                                      peer_kx_pk) != 0)
        gm_die("key exchange failed");
    if (start_crypto(session) != 0) gm_die("crypto setup failed");

    uint8_t *challenge = NULL;
    uint8_t msg_type = 0;
    uint32_t msg_len = 0;
    if (gm_recv_msg(session, &msg_type, &challenge, &msg_len) != 0 ||
        msg_type != HP_CHALLENGE || msg_len != 32) {
        gm_close(session);
        gm_die("auth: no challenge");
    }
    uint8_t transcript[3 + 32 + 2 * crypto_kx_PUBLICKEYBYTES];
    memcpy(transcript, "GM1", 3);
    memcpy(transcript + 3, challenge, 32);
    memcpy(transcript + 35, peer_kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(transcript + 35 + crypto_kx_PUBLICKEYBYTES, id.kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    free(challenge);

    uint8_t signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, NULL, transcript, sizeof transcript, id.sign_sk);
    if (gm_send_msg(session, HP_AUTH, signature, sizeof signature) != 0) {
        gm_close(session);
        gm_die("auth: send failed");
    }

    uint8_t *server_signature = NULL;
    if (gm_recv_msg(session, &msg_type, &server_signature, &msg_len) != 0 ||
        (msg_type != HP_AUTH && msg_type != GM_ERR)) {
        gm_close(session);
        gm_die("auth: no reply");
    }
    if (msg_type == GM_ERR) {
        gm_close(session);
        gm_die("auth rejected by peer");
    }
    if (msg_len != crypto_sign_BYTES ||
        crypto_sign_verify_detached(server_signature, transcript, sizeof transcript,
                                    session->peer_sign_pk) != 0) {
        gm_close(session);
        gm_die("auth: peer signature invalid");
    }
    free(server_signature);
    return session;
}

gm_sess *gm_serve(int fd) {
    gm_ident id;
    if (gm_ident_load(&id) != 0) gm_die("identity load failed");

    gm_sess *session = calloc(1, sizeof *session);
    session->fd = fd;
    session->server = true;

    uint8_t peer_kx_pk[crypto_kx_PUBLICKEYBYTES];
    if (recv_hello(session, peer_kx_pk) != 0 || send_hello(session, &id) != 0) {
        gm_close(session);
        return NULL;
    }
    if (crypto_kx_server_session_keys(session->rx_key, session->tx_key, id.kx_pk, id.kx_sk,
                                      peer_kx_pk) != 0) {
        gm_close(session);
        return NULL;
    }
    if (start_crypto(session) != 0) {
        gm_close(session);
        return NULL;
    }

    uint8_t challenge[32];
    randombytes_buf(challenge, sizeof challenge);
    if (gm_send_msg(session, HP_CHALLENGE, challenge, sizeof challenge) != 0) {
        gm_close(session);
        return NULL;
    }

    uint8_t *signature = NULL;
    uint8_t msg_type = 0;
    uint32_t msg_len = 0;
    if (gm_recv_msg(session, &msg_type, &signature, &msg_len) != 0 ||
        msg_type != HP_AUTH || msg_len != crypto_sign_BYTES) {
        gm_close(session);
        return NULL;
    }
    uint8_t transcript[3 + 32 + 2 * crypto_kx_PUBLICKEYBYTES];
    memcpy(transcript, "GM1", 3);
    memcpy(transcript + 3, challenge, 32);
    memcpy(transcript + 35, id.kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(transcript + 35 + crypto_kx_PUBLICKEYBYTES, peer_kx_pk,
           crypto_kx_PUBLICKEYBYTES);
    int verified = crypto_sign_verify_detached(signature, transcript, sizeof transcript,
                                               session->peer_sign_pk) == 0;
    free(signature);
    if (!verified) {
        gm_send_msg(session, GM_ERR, "bad signature", 13);
        gm_close(session);
        return NULL;
    }
    uint8_t server_signature[crypto_sign_BYTES];
    crypto_sign_detached(server_signature, NULL, transcript, sizeof transcript, id.sign_sk);
    if (gm_send_msg(session, HP_AUTH, server_signature, sizeof server_signature) != 0) {
        gm_close(session);
        return NULL;
    }
    return session;
}

int gm_listen(uint16_t port) {
    gm_sock_init();
    if (port == 0) port = GM_TCP_PORT;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int enable = 1;
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof enable);
#endif
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof enable);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(fd, 8) != 0) {
        gm_sock_close(fd);
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
