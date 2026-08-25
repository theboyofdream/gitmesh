#ifndef GITMESH_H
#define GITMESH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

#define GM_VERSION       "0.1.0"
#define GM_PROTO_VERSION 1

#define GM_DISCO_PORT 42997
#define GM_TCP_PORT   42998
#define GM_MAGIC      "GITMESH1"

#define GM_NAME_MAX  64
#define GM_PATH_MAX  4096
#define GM_CHUNK     (64 * 1024)
#define GM_FRAME_MAX (4 * 1024 * 1024)

typedef struct {
    uint8_t seed[crypto_sign_SEEDBYTES];
    uint8_t sign_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sign_sk[crypto_sign_SECRETKEYBYTES];
    uint8_t kx_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t kx_sk[crypto_kx_SECRETKEYBYTES];
    char user[GM_NAME_MAX];
    char device[GM_NAME_MAX];
} gm_ident;

static inline void gm_ident_display(const gm_ident *id, char out[GM_NAME_MAX]) {
    if (id->user[0] && strcmp(id->user, id->device) != 0)
        snprintf(out, GM_NAME_MAX, "%s@%s", id->user, id->device);
    else
        snprintf(out, GM_NAME_MAX, "%s", id->device);
}

typedef struct {
    char ip[48];
    uint16_t port;
    char name[GM_NAME_MAX];
    uint8_t sign_pk[crypto_sign_PUBLICKEYBYTES];
    int64_t seen_ms;
} gm_peer;

typedef struct {
    char *path;
    uint8_t hash[crypto_generichash_BYTES];
    uint64_t size;
    int64_t mtime;
} gm_entry;

typedef struct {
    gm_entry *v;
    size_t n;
    size_t cap;
} gm_manifest;

enum {
    GM_GET_MANIFEST = 5,
    GM_PUSH_MANIFEST = 6,
    GM_SYNC_PLAN = 7,
    GM_WANT = 8,
    GM_FILE_HDR = 9,
    GM_FILE_DATA = 10,
    GM_DONE = 11,
    GM_ERR = 12,
    GM_MANIFEST = 13,
};

void gm_die(const char *fmt, ...);
void *gm_xmalloc(size_t n);
void *gm_xrealloc(void *p, size_t n);
char *gm_xstrdup(const char *s);
void gm_hex(char *out, const uint8_t *in, size_t n);
int gm_unhex(uint8_t *out, size_t outn, const char *in);
int gm_home_path(char *buf, size_t n, const char *rel);
int gm_read_file(const char *path, uint8_t **out, size_t *outn);
int gm_write_file_atomic(const char *root, const char *rel, const uint8_t *data, size_t n);
void gm_gethostname(char *buf, size_t n);
int64_t gm_now_ms(void);

int gm_ident_load(gm_ident *id);
int gm_ident_set_user(const char *name);
int gm_ident_set_device(const char *name);
int gm_ident_export(char *out, size_t n);
int gm_ident_import(const char *hex);
void gm_known_pin(const gm_ident *me, const uint8_t *peer_pk, const char *name);
char *gm_known_name(const uint8_t *peer_pk);
bool gm_known_check(const uint8_t *peer_pk);

void gm_disco_run(const gm_ident *id, uint16_t tcp_port);
int gm_disco_collect(const gm_ident *id, gm_peer *out, int max, int ms);
int gm_disco_resolve(const gm_ident *id, const char *name, char *ip, uint16_t *port, uint8_t *pk);
uint16_t gm_env_tcp_port(void);

void gm_manifest_free(gm_manifest *m);
void gm_manifest_sort(gm_manifest *m);
gm_entry *gm_manifest_find(const gm_manifest *m, const char *path);
void gm_manifest_push(gm_manifest *m, const gm_entry *e);
int gm_index_load(const char *root, gm_manifest *m);
int gm_index_save(const char *root, const gm_manifest *m);
int gm_scan(const char *root, const gm_manifest *old, gm_manifest *out);
void gm_diff(const gm_manifest *old, const gm_manifest *cur, size_t *added, size_t *modified, size_t *deleted);

typedef struct gm_sess gm_sess;

int gm_listen(uint16_t port);
gm_sess *gm_connect(const char *ip, uint16_t port);
gm_sess *gm_serve(int fd);
const char *gm_sess_peer_name(gm_sess *s);
const uint8_t *gm_sess_peer_pk(gm_sess *s);
int gm_send_msg(gm_sess *s, uint8_t type, const void *payload, uint32_t len);
int gm_recv_msg(gm_sess *s, uint8_t *type, uint8_t **payload, uint32_t *len);
void gm_close(gm_sess *s);

int gm_cmd_share(void);
int gm_cmd_send(const char *peer);
int gm_cmd_receive(const char *peer);
#endif
