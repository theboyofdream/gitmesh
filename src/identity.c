#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void mkdirs(char *path) {
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(path, 0755);
            *p = '/';
        }
    }
    mkdir(path, 0755);
}

static void trim_nl(char *s, size_t *n) {
    while (*n && (s[*n - 1] == '\n' || s[*n - 1] == '\r')) (*n)--;
    s[*n] = 0;
}

static void load_name_file(const char *rel, char *out) {
    char path[GM_PATH_MAX];
    if (gm_home_path(path, sizeof path, rel) != 0) return;
    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(path, &data, &n) != 0) return;
    if (n == 0 || n > GM_NAME_MAX) { free(data); return; }
    trim_nl((char *)data, &n);
    if (n > 0) snprintf(out, GM_NAME_MAX, "%s", (char *)data);
    free(data);
}

int gm_ident_load(gm_ident *id) {
    char dir[GM_PATH_MAX], file[GM_PATH_MAX];
    if (gm_home_path(dir, sizeof dir, "") != 0) gm_die("cannot find HOME");
    mkdirs(dir);
    if (gm_home_path(file, sizeof file, "identity") != 0) return -1;

    uint8_t seed[crypto_sign_SEEDBYTES];
    char hexbuf[crypto_sign_SEEDBYTES * 2 + 1];

    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(file, &data, &n) != 0 ||
        gm_unhex(seed, sizeof seed, (const char *)data) != 0) {
        randombytes_buf(seed, sizeof seed);
        FILE *f = fopen(file, "wb");
        if (!f) gm_die("cannot write %s", file);
        gm_hex(hexbuf, seed, sizeof seed);
        fputs(hexbuf, f);
        fclose(f);
    }
    free(data);

    memcpy(id->seed, seed, sizeof seed);
    crypto_sign_seed_keypair(id->sign_pk, id->sign_sk, seed);
    crypto_kx_seed_keypair(id->kx_pk, id->kx_sk, seed);

    char host[128];
    gm_gethostname(host, sizeof host);
    host[GM_NAME_MAX - 1] = 0;
    snprintf(id->device, sizeof id->device, "%s", host);
    load_name_file("device", id->device);

    id->user[0] = 0;
    load_name_file("user", id->user);
    if (!id->user[0]) load_name_file("name", id->user);
    if (!id->user[0]) snprintf(id->user, sizeof id->user, "%s", id->device);

    return 0;
}

int gm_ident_set_user(const char *name) {
    if (!name || !*name || strlen(name) >= GM_NAME_MAX) return -1;
    for (const char *p = name; *p; p++) if (*p == '\n' || *p == '\r') return -1;
    char path[GM_PATH_MAX];
    if (gm_home_path(path, sizeof path, "user") != 0) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "%s\n", name);
    fclose(f);
    return 0;
}

int gm_ident_set_device(const char *name) {
    if (!name || !*name || strlen(name) >= GM_NAME_MAX) return -1;
    for (const char *p = name; *p; p++) if (*p == '\n' || *p == '\r') return -1;
    char path[GM_PATH_MAX];
    if (gm_home_path(path, sizeof path, "device") != 0) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "%s\n", name);
    fclose(f);
    return 0;
}

int gm_ident_export(char *out, size_t n) {
    gm_ident id;
    if (gm_ident_load(&id) != 0) return -1;
    if (n < crypto_sign_SEEDBYTES * 2 + 1) return -1;
    gm_hex(out, id.seed, crypto_sign_SEEDBYTES);
    return 0;
}

int gm_ident_import(const char *hex) {
    uint8_t seed[crypto_sign_SEEDBYTES];
    if (!hex || gm_unhex(seed, sizeof seed, hex) != 0) return -1;
    char path[GM_PATH_MAX], hexbuf[crypto_sign_SEEDBYTES * 2 + 1];
    if (gm_home_path(path, sizeof path, "identity") != 0) return -1;
    for (char *p = path + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(path, 0755); *p = '/'; }
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    gm_hex(hexbuf, seed, sizeof seed);
    fputs(hexbuf, f);
    fclose(f);
    return 0;
}

static void known_file(char *buf, size_t n) {
    if (gm_home_path(buf, n, "known_peers") != 0) buf[0] = 0;
}

bool gm_known_check(const uint8_t *peer_pk) {
    char path[GM_PATH_MAX];
    known_file(path, sizeof path);
    if (!path[0]) return false;
    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(path, &data, &n) != 0) return false;
    char want[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    gm_hex(want, peer_pk, crypto_sign_PUBLICKEYBYTES);
    bool found = false;
    char *line = (char *)data;
    for (size_t i = 0; i <= n && !found; i++) {
        if (i == n || data[i] == '\n') {
            size_t len = (size_t)(data + i - (uint8_t *)line);
            while (len && line[len - 1] == '\r') len--;
            if (len >= crypto_sign_PUBLICKEYBYTES * 2 &&
                memcmp(line, want, crypto_sign_PUBLICKEYBYTES * 2) == 0)
                found = true;
            line = (char *)data + i + 1;
        }
    }
    free(data);
    return found;
}

void gm_known_pin(const gm_ident *me, const uint8_t *peer_pk, const char *name) {
    (void)me;
    char path[GM_PATH_MAX];
    known_file(path, sizeof path);
    if (!path[0] || gm_known_check(peer_pk)) return;
    char pkhex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    gm_hex(pkhex, peer_pk, crypto_sign_PUBLICKEYBYTES);
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%s %s\n", pkhex, name ? name : "?");
    fclose(f);
    fprintf(stderr, "gitmesh: pinned new peer %s (%s)\n", name ? name : "?", pkhex + 56);
}

char *gm_known_name(const uint8_t *peer_pk) {
    char path[GM_PATH_MAX];
    known_file(path, sizeof path);
    if (!path[0]) return NULL;
    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(path, &data, &n) != 0) return NULL;
    char want[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    gm_hex(want, peer_pk, crypto_sign_PUBLICKEYBYTES);
    char *found = NULL;
    char *line = (char *)data;
    for (size_t i = 0; i <= n && !found; i++) {
        if (i == n || data[i] == '\n') {
            size_t len = (size_t)(data + i - (uint8_t *)line);
            while (len && (line[len - 1] == '\r' || line[len - 1] == ' ')) len--;
            if (len > crypto_sign_PUBLICKEYBYTES * 2 + 1 &&
                memcmp(line, want, crypto_sign_PUBLICKEYBYTES * 2) == 0 &&
                line[crypto_sign_PUBLICKEYBYTES * 2] == ' ') {
                found = gm_xstrdup(line + crypto_sign_PUBLICKEYBYTES * 2 + 1);
                found[len - crypto_sign_PUBLICKEYBYTES * 2 - 1] = 0;
            }
            line = (char *)data + i + 1;
        }
    }
    free(data);
    return found;
}
