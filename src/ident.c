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

int gm_ident_load(gm_ident *id) {
    char dir[GM_PATH_MAX], file[GM_PATH_MAX], namefile[GM_PATH_MAX];
    if (gm_home_path(dir, sizeof dir, "") != 0) gm_die("cannot find HOME");
    mkdirs(dir);
    if (gm_home_path(file, sizeof file, "identity") != 0) return -1;

    uint8_t seed[crypto_sign_SEEDBYTES];
    char hexbuf[crypto_sign_SEEDBYTES * 2 + 1];

    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(file, &data, &n) != 0 ||
        n < sizeof seed || gm_unhex(seed, sizeof seed, (const char *)data) != 0) {
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
    snprintf(id->name, sizeof id->name, "%s", host);
    if (gm_home_path(namefile, sizeof namefile, "name") == 0) {
        uint8_t *nd = NULL;
        size_t nn = 0;
        if (gm_read_file(namefile, &nd, &nn) == 0 && nn > 0 && nn <= GM_NAME_MAX) {
            while (nn && (nd[nn - 1] == '\n' || nd[nn - 1] == '\r')) nn--;
            if (nn > 0) {
                memcpy(id->name, nd, nn);
                id->name[nn] = 0;
            }
        }
        free(nd);
    }
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
