#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lz4.h>



static bool parse_addr(const char *peer, char *ip, uint16_t *port) {
    int a, b, c, d, p;
    if (sscanf(peer, "%d.%d.%d.%d:%d", &a, &b, &c, &d, &p) == 5) {
        if (a >= 0 && a < 256 && b >= 0 && b < 256 && c >= 0 && c < 256 && d >= 0 && d < 256 && p > 0 && p < 65536) {
            snprintf(ip, 48, "%d.%d.%d.%d", a, b, c, d);
            *port = (uint16_t)p;
            return true;
        }
    }
    return false;
}

static uint8_t *manifest_encode(const gm_manifest *m, size_t *outn) {
    size_t n = 4;
    for (size_t i = 0; i < m->n; i++)
        n += 2 + strlen(m->v[i].path) + crypto_generichash_BYTES + 8;
    uint8_t *buf = gm_xmalloc(n);
    uint32_t count = (uint32_t)m->n;
    memcpy(buf, &count, 4);
    size_t off = 4;
    for (size_t i = 0; i < m->n; i++) {
        uint16_t plen = (uint16_t)strlen(m->v[i].path);
        memcpy(buf + off, &plen, 2);
        off += 2;
        memcpy(buf + off, m->v[i].path, plen);
        off += plen;
        memcpy(buf + off, m->v[i].hash, crypto_generichash_BYTES);
        off += crypto_generichash_BYTES;
        memcpy(buf + off, &m->v[i].size, 8);
        off += 8;
    }
    *outn = off;
    return buf;
}

static int manifest_decode(const uint8_t *data, size_t n, gm_manifest *m) {
    memset(m, 0, sizeof *m);
    if (n < 4) return -1;
    uint32_t count;
    memcpy(&count, data, 4);
    size_t off = 4;
    for (uint32_t i = 0; i < count; i++) {
        if (off + 2 > n) goto bad;
        uint16_t plen;
        memcpy(&plen, data + off, 2);
        off += 2;
        if (off + (size_t)plen + crypto_generichash_BYTES + 8 > n) goto bad;
        gm_entry e = {0};
        e.path = gm_xmalloc((size_t)plen + 1);
        memcpy(e.path, data + off, plen);
        e.path[plen] = 0;
        off += plen;
        memcpy(e.hash, data + off, crypto_generichash_BYTES);
        off += crypto_generichash_BYTES;
        memcpy(&e.size, data + off, 8);
        off += 8;
        gm_manifest_push(m, &e);
    }
    gm_manifest_sort(m);
    return 0;
bad:
    gm_manifest_free(m);
    return -1;
}

typedef struct {
    uint32_t *want;
    size_t n_want;
    char **del;
    size_t n_del;
    char **conflict;
    size_t n_conflict;
} gm_plan;

static void plan_free(gm_plan *p) {
    free(p->want);
    for (size_t i = 0; i < p->n_del; i++) free(p->del[i]);
    free(p->del);
    for (size_t i = 0; i < p->n_conflict; i++) free(p->conflict[i]);
    free(p->conflict);
    memset(p, 0, sizeof *p);
}

static void plan_push_conflict(gm_plan *p, const char *path) {
    p->conflict = gm_xrealloc(p->conflict, (p->n_conflict + 1) * sizeof(char *));
    p->conflict[p->n_conflict++] = gm_xstrdup(path);
}

static bool valid_rel_path(const char *path) {
    if (!path || !*path || path[0] == '/' || strstr(path, "..")) return false;
    for (const char *p = path; *p; p++)
        if (*p == '\\') return false;
    return true;
}

static void plan_compute(const gm_manifest *peer, const gm_manifest *mine,
                         const gm_manifest *idx, gm_plan *p) {
    memset(p, 0, sizeof *p);
    for (size_t j = 0; j < peer->n; j++) {
        const gm_entry *pe = &peer->v[j];
        if (!valid_rel_path(pe->path)) {
            plan_push_conflict(p, pe->path);
            continue;
        }
        const gm_entry *me = gm_manifest_find(mine, pe->path);
        if (!me) {
            p->want = gm_xrealloc(p->want, (p->n_want + 1) * sizeof(uint32_t));
            p->want[p->n_want++] = (uint32_t)j;
            continue;
        }
        if (memcmp(me->hash, pe->hash, crypto_generichash_BYTES) == 0) continue;
        const gm_entry *ie = gm_manifest_find(idx, pe->path);
        if (!ie || memcmp(ie->hash, me->hash, crypto_generichash_BYTES) == 0) {
            p->want = gm_xrealloc(p->want, (p->n_want + 1) * sizeof(uint32_t));
            p->want[p->n_want++] = (uint32_t)j;
        } else {
            plan_push_conflict(p, pe->path);
        }
    }
    for (size_t i = 0; i < idx->n; i++) {
        const gm_entry *ie = &idx->v[i];
        if (gm_manifest_find(peer, ie->path)) continue;
        const gm_entry *me = gm_manifest_find(mine, ie->path);
        if (!me || memcmp(me->hash, ie->hash, crypto_generichash_BYTES) == 0) {
            p->del = gm_xrealloc(p->del, (p->n_del + 1) * sizeof(char *));
            p->del[p->n_del++] = gm_xstrdup(ie->path);
        } else {
            plan_push_conflict(p, ie->path);
        }
    }
}

static int send_file(gm_sess *s, const char *root, const char *path,
                     const uint8_t hash[crypto_generichash_BYTES]) {
    char full[GM_PATH_MAX];
    if (snprintf(full, sizeof full, "%s/%s", root, path) >= (int)sizeof full)
        return -1;
    FILE *f = fopen(full, "rb");
    if (!f) return -1;

    size_t hl = 2 + strlen(path) + 8 + crypto_generichash_BYTES;
    uint8_t *hdr = gm_xmalloc(hl);
    uint16_t plen = (uint16_t)strlen(path);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        free(hdr);
        return -1;
    }
    uint64_t fsize = (uint64_t)sz;
    memcpy(hdr, &plen, 2);
    memcpy(hdr + 2, path, plen);
    memcpy(hdr + 2 + plen, &fsize, 8);
    memcpy(hdr + 2 + plen + 8, hash, crypto_generichash_BYTES);

    int rc = gm_send_msg(s, GM_FILE_HDR, hdr, (uint32_t)hl);
    free(hdr);
    if (rc != 0) {
        fclose(f);
        return -1;
    }

    uint8_t *buf = gm_xmalloc(GM_CHUNK);
    uint8_t *comp = gm_xmalloc(LZ4_compressBound(GM_CHUNK));
    uint64_t sent = 0;
    while (sent < fsize) {
        size_t chunk = fsize - sent > GM_CHUNK ? GM_CHUNK : (size_t)(fsize - sent);
        if (fread(buf, 1, chunk, f) != chunk) {
            rc = -1;
            break;
        }
        int clen = LZ4_compress_default((const char *)buf, (char *)comp,
                                        (int)chunk, LZ4_compressBound((int)chunk));
        uint8_t *payload;
        uint32_t wire;
        if (clen > 0 && (size_t)clen + 5 < chunk) {
            wire = 5 + (uint32_t)clen;
            payload = gm_xmalloc(wire);
            payload[0] = 1;
            memcpy(payload + 1, &clen, 4);
            memcpy(payload + 5, comp, (size_t)clen);
        } else {
            uint32_t rawlen = (uint32_t)chunk;
            wire = 5 + rawlen;
            payload = gm_xmalloc(wire);
            payload[0] = 0;
            memcpy(payload + 1, &rawlen, 4);
            memcpy(payload + 5, buf, chunk);
        }
        if (gm_send_msg(s, GM_FILE_DATA, payload, wire) != 0)
            rc = -1;
        free(payload);
        if (rc != 0) break;
        sent += chunk;
        printf("\r  %s %llu / %llu", path, (unsigned long long)sent,
               (unsigned long long)fsize);
        fflush(stdout);
    }
    printf("\n");
    fclose(f);
    free(buf);
    free(comp);
    return rc;
}

static void print_progress(uint64_t got, uint64_t total) {
    printf("\r  %llu / %llu bytes", (unsigned long long)got,
           (unsigned long long)total);
    fflush(stdout);
}

static int finish_file(const char *root, const char *path,
                       const uint8_t hash[crypto_generichash_BYTES],
                       uint8_t *data, uint64_t size, gm_manifest *applied) {
    uint8_t check[crypto_generichash_BYTES];
    crypto_generichash(check, sizeof check, data, size, NULL, 0);
    if (memcmp(check, hash, sizeof check) != 0) {
        fprintf(stderr, "\nhash mismatch: %s\n", path);
        return -1;
    }
    if (gm_write_file_atomic(root, path, data, (size_t)size) != 0) {
        fprintf(stderr, "\nwrite failed: %s\n", path);
        return -1;
    }
    struct stat st;
    char full[GM_PATH_MAX];
    snprintf(full, sizeof full, "%s/%s", root, path);
    gm_entry e = {0};
    e.path = gm_xstrdup(path);
    e.size = size;
    memcpy(e.hash, hash, crypto_generichash_BYTES);
    e.mtime = stat(full, &st) == 0 ? gm_st_mtime_ms(&st) : gm_now_ms();
    gm_manifest_push(applied, &e);
    return 0;
}

/* Receive FILE_HDR/DATA frames until DONE. Writes verified files atomically. */
static int recv_files(gm_sess *s, const char *root, gm_manifest *applied) {
    uint8_t type = 0;
    uint8_t *payload = NULL;
    uint32_t len = 0;

    char cur_path[GM_PATH_MAX] = {0};
    uint8_t cur_hash[crypto_generichash_BYTES] = {0};
    uint64_t cur_size = 0, got = 0;
    uint8_t *cur_data = NULL;

    for (;;) {
        if (gm_recv_msg(s, &type, &payload, &len) != 0) goto fail;
        if (type == GM_DONE) {
            free(payload);
            printf("\n");
            return 0;
        }
        if (type == GM_ERR) {
            fprintf(stderr, "\npeer error: %.*s\n",
                    (int)(len > 200 ? 200 : len), (const char *)payload);
            free(payload);
            goto fail;
        }

        if (type == GM_FILE_HDR) {
            if (got != cur_size) goto fail;
            free(cur_data);
            cur_data = NULL;
            cur_path[0] = 0;
            if (len < 2u + crypto_generichash_BYTES + 8) goto fail;
            uint16_t plen;
            memcpy(&plen, payload, 2);
            if (2u + plen + crypto_generichash_BYTES + 8 != len ||
                plen >= sizeof cur_path)
                goto fail;
            memcpy(cur_path, payload + 2, plen);
            cur_path[plen] = 0;
            memcpy(&cur_size, payload + 2 + plen, 8);
            memcpy(cur_hash, payload + 2 + plen + 8, crypto_generichash_BYTES);
            if (!valid_rel_path(cur_path)) goto fail;
            cur_data = gm_xmalloc(cur_size ? (size_t)cur_size : 1);
            got = 0;
        } else if (type == GM_FILE_DATA) {
            if (!cur_data || len < 5) goto fail;
            uint8_t flag = payload[0];
            uint32_t clen;
            memcpy(&clen, payload + 1, 4);
            if ((size_t)clen + 5 != len) goto fail;
            if (flag == 1) {
                if (got >= cur_size) goto fail;
                int out = LZ4_decompress_safe((const char *)payload + 5,
                                              (char *)cur_data + got, (int)clen,
                                              (int)(cur_size - got));
                if (out < 0) goto fail;
                got += (uint64_t)out;
            } else {
                if (got + clen > cur_size) goto fail;
                memcpy(cur_data + got, payload + 5, clen);
                got += clen;
            }
            print_progress(got, cur_size);

            if (got == cur_size) {
                if (finish_file(root, cur_path, cur_hash, cur_data, cur_size,
                                applied) != 0)
                    goto fail;
                free(cur_data);
                cur_data = NULL;
                cur_path[0] = 0;
                printf("\n");
            }
        } else {
            goto fail;
        }
        free(payload);
        payload = NULL;
    }
fail:
    free(payload);
    free(cur_data);
    return -1;
}

static void apply_deletes(const char *root, gm_plan *p, gm_manifest *idx) {
    for (size_t i = 0; i < p->n_del; i++) {
        char full[GM_PATH_MAX];
        snprintf(full, sizeof full, "%s/%s", root, p->del[i]);
        unlink(full);
        for (size_t j = 0; j < idx->n; j++) {
            if (strcmp(idx->v[j].path, p->del[i]) == 0) {
                free(idx->v[j].path);
                memmove(&idx->v[j], &idx->v[j + 1],
                        (idx->n - j - 1) * sizeof *idx->v);
                idx->n--;
                break;
            }
        }
        printf("deleted %s\n", p->del[i]);
    }
}

static int send_plan(gm_sess *s, const gm_plan *p) {
    size_t n = 12 + p->n_want * 4;
    for (size_t i = 0; i < p->n_del; i++) n += 2 + strlen(p->del[i]);
    for (size_t i = 0; i < p->n_conflict; i++) n += 2 + strlen(p->conflict[i]);
    uint8_t *buf = gm_xmalloc(n);
    uint32_t w = (uint32_t)p->n_want;
    memcpy(buf, &w, 4);
    size_t off = 4;
    for (size_t i = 0; i < p->n_want; i++) {
        memcpy(buf + off, &p->want[i], 4);
        off += 4;
    }
    uint32_t d = (uint32_t)p->n_del;
    memcpy(buf + off, &d, 4);
    off += 4;
    for (size_t i = 0; i < p->n_del; i++) {
        uint16_t plen = (uint16_t)strlen(p->del[i]);
        memcpy(buf + off, &plen, 2);
        off += 2;
        memcpy(buf + off, p->del[i], plen);
        off += plen;
    }
    uint32_t c = (uint32_t)p->n_conflict;
    memcpy(buf + off, &c, 4);
    off += 4;
    for (size_t i = 0; i < p->n_conflict; i++) {
        uint16_t plen = (uint16_t)strlen(p->conflict[i]);
        memcpy(buf + off, &plen, 2);
        off += 2;
        memcpy(buf + off, p->conflict[i], plen);
        off += plen;
    }
    return gm_send_msg(s, GM_SYNC_PLAN, buf, (uint32_t)off);
}

static void merge_index(gm_manifest *idx, const gm_manifest *applied) {
    for (size_t i = 0; i < applied->n; i++) {
        gm_entry *e = gm_manifest_find(idx, applied->v[i].path);
        if (e) {
            memcpy(e->hash, applied->v[i].hash, crypto_generichash_BYTES);
            e->size = applied->v[i].size;
            e->mtime = applied->v[i].mtime;
        } else {
            gm_entry copy = applied->v[i];
            copy.path = gm_xstrdup(applied->v[i].path);
            gm_manifest_push(idx, &copy);
            gm_manifest_sort(idx);
        }
    }
}

static int parse_plan(const uint8_t *data, size_t n, gm_plan *p) {
    memset(p, 0, sizeof *p);
    size_t off = 0;
#define TAKE_U32(v)                                  \
    do {                                             \
        if (off + 4 > n) return -1;                  \
        memcpy(&(v), data + off, 4);                 \
        off += 4;                                    \
    } while (0)

    uint32_t want_n_u32 = 0, del_n_u32 = 0, con_n_u32 = 0;
    TAKE_U32(want_n_u32);
    p->want = NULL;
    p->n_want = 0;
    if (want_n_u32 > GM_FRAME_MAX / 4) return -1;
    for (uint32_t i = 0; i < want_n_u32; i++) {
        uint32_t v;
        TAKE_U32(v);
        p->want = gm_xrealloc(p->want, (p->n_want + 1) * sizeof(uint32_t));
        p->want[p->n_want++] = v;
    }
    TAKE_U32(del_n_u32);
    {
        p->del = NULL;
        p->n_del = 0;
        for (uint32_t i = 0; i < del_n_u32; i++) {
            if (off + 2 > n) return -1;
            uint16_t plen;
            memcpy(&plen, data + off, 2);
            off += 2;
            if (off + plen > n) return -1;
            char *s = gm_xmalloc((size_t)plen + 1);
            memcpy(s, data + off, plen);
            s[plen] = 0;
            off += plen;
            p->del = gm_xrealloc(p->del, (p->n_del + 1) * sizeof(char *));
            p->del[p->n_del++] = s;
        }
    }
    TAKE_U32(con_n_u32);
    {
        p->conflict = NULL;
        p->n_conflict = 0;
        for (uint32_t i = 0; i < con_n_u32; i++) {
            if (off + 2 > n) return -1;
            uint16_t plen;
            memcpy(&plen, data + off, 2);
            off += 2;
            if (off + plen > n) return -1;
            char *s = gm_xmalloc((size_t)plen + 1);
            memcpy(s, data + off, plen);
            s[plen] = 0;
            off += plen;
            p->conflict = gm_xrealloc(p->conflict, (p->n_conflict + 1) * sizeof(char *));
            p->conflict[p->n_conflict++] = s;
        }
    }
#undef TAKE_U32
    return 0;
}

static bool confirm(const char *question) {
    printf("%s [y/N] ", question);
    fflush(stdout);
    char buf[16] = {0};
    if (!fgets(buf, sizeof buf, stdin)) return false;
    return buf[0] == 'y' || buf[0] == 'Y';
}

#ifndef _WIN32
#include <signal.h>
#endif

static void serve_session(int fd) {
    gm_sess *s = gm_serve(fd);
    if (!s) return;
    const uint8_t *pk = gm_sess_peer_pk(s);
    if (!gm_known_check(pk))
        gm_known_pin(NULL, pk, gm_sess_peer_name(s));

    uint8_t type = 0;
    uint8_t *payload = NULL;
    uint32_t len = 0;
    if (gm_recv_msg(s, &type, &payload, &len) != 0) {
        gm_close(s);
        return;
    }

    if (type == GM_GET_MANIFEST) {
        free(payload);
        gm_manifest old = {0}, cur = {0};
        gm_index_load(".", &old);
        gm_scan(".", &old, &cur);
        size_t n = 0;
        uint8_t *enc = manifest_encode(&cur, &n);
        gm_send_msg(s, GM_MANIFEST, enc, (uint32_t)n);
        free(enc);
        uint8_t wtype = 0;
        uint8_t *wpayload = NULL;
        uint32_t wlen = 0;
        if (gm_recv_msg(s, &wtype, &wpayload, &wlen) == 0 && wtype == GM_WANT) {
            uint32_t count = wlen / 4;
            int rc = 0;
            for (uint32_t i = 0; i < count && rc == 0; i++) {
                uint32_t idx;
                memcpy(&idx, wpayload + i * 4, 4);
                if (idx >= cur.n) rc = -1;
                else rc = send_file(s, ".", cur.v[idx].path, cur.v[idx].hash);
            }
            if (rc == 0) gm_send_msg(s, GM_DONE, "complete", 8);
            else gm_send_msg(s, GM_ERR, "transfer failed", 15);
            free(wpayload);
        } else {
            free(wpayload);
        }
        gm_manifest_free(&old);
        gm_manifest_free(&cur);
    } else if (type == GM_PUSH_MANIFEST) {
        gm_manifest theirs = {0};
        if (manifest_decode(payload, len, &theirs) != 0) {
            free(payload);
            gm_send_msg(s, GM_ERR, "bad manifest", 12);
            gm_close(s);
            return;
        }
        free(payload);
        gm_manifest old = {0}, mine = {0};
        gm_index_load(".", &old);
        gm_scan(".", &old, &mine);
        gm_plan plan;
        plan_compute(&theirs, &mine, &old, &plan);
        send_plan(s, &plan);

        gm_manifest applied = {0};
        if (recv_files(s, ".", &applied) == 0) {
            apply_deletes(".", &plan, &old);
            merge_index(&old, &applied);
            gm_index_save(".", &old);
            char msg[128];
            snprintf(msg, sizeof msg, "%zu file(s) applied", applied.n);
            gm_send_msg(s, GM_DONE, msg, (uint32_t)strlen(msg));
        } else {
            gm_send_msg(s, GM_ERR, "transfer failed", 15);
        }
        plan_free(&plan);
        gm_manifest_free(&theirs);
        gm_manifest_free(&old);
        gm_manifest_free(&mine);
        gm_manifest_free(&applied);
    } else {
        free(payload);
        gm_send_msg(s, GM_ERR, "unknown request", 15);
    }
    gm_close(s);
}

int gm_cmd_share(void) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    if (gm_sock_init() != 0) gm_die("socket init failed");
    gm_ident id;
    gm_ident_load(&id);
    uint16_t tport = gm_env_tcp_port();
    int lfd = gm_listen(tport);
    if (lfd < 0) gm_die("cannot listen on TCP %d", tport);
    char display[GM_NAME_MAX];
    gm_ident_display(&id, display);
    printf("gitmesh %s — sharing '%s'\n", GM_VERSION, display);
    int64_t last_announce = 0;
    for (;;) {
        int64_t now = gm_now_ms();
        if (now - last_announce >= 2000) {
            gm_disco_run(&id, tport);
            last_announce = now;
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
        if (select(lfd + 1, &rfds, NULL, NULL, &tv) > 0) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd >= 0)
                serve_session(cfd);
        }
    }
}

static void resolve_or_die(const gm_ident *id, const char *peer,
                           char *ip, uint16_t *port, uint8_t *pk) {
    if (parse_addr(peer, ip, port)) {
        memset(pk, 0, crypto_sign_PUBLICKEYBYTES);
        return;
    }
    printf("looking for %s...\n", peer);
    if (gm_disco_resolve(id, peer, ip, port, pk) != 0)
        gm_die("peer '%s' not found online", peer);
}

static void project_root(char *root, size_t n) {
    if (!getcwd(root, n)) gm_die("cannot determine working directory");
}

int gm_cmd_send(const char *peer) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    gm_sock_init();
    gm_ident id;
    gm_ident_load(&id);
    char ip[48];
    uint16_t port = gm_env_tcp_port();
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    resolve_or_die(&id, peer, ip, &port, pk);
    if (pk[0] || pk[1]) {
        if (!gm_known_check(pk)) gm_known_pin(NULL, pk, peer);
    }

    char root[GM_PATH_MAX];
    project_root(root, sizeof root);

    gm_manifest old = {0}, cur = {0};
    gm_index_load(root, &old);
    gm_scan(root, &old, &cur);
    size_t added = 0, modified = 0, deleted = 0;
    gm_diff(&old, &cur, &added, &modified, &deleted);
    printf("\n%zu file(s) changed\n%zu file(s) added\n%zu file(s) deleted\n",
           modified, added, deleted);
    if (added + modified + deleted == 0) {
        printf("nothing to send\n");
        gm_manifest_free(&old);
        gm_manifest_free(&cur);
        return 0;
    }
    if (!confirm("send?")) {
        printf("aborted\n");
        gm_manifest_free(&old);
        gm_manifest_free(&cur);
        return 1;
    }

    printf("\nconnecting %s (%s:%u)\n", peer, ip, port);
    gm_sess *s = gm_connect(ip, port);
    {
        const uint8_t *spk = gm_sess_peer_pk(s);
        if (!gm_known_check(spk)) gm_known_pin(NULL, spk, peer);
    }
    size_t n = 0;
    uint8_t *enc = manifest_encode(&cur, &n);
    int rc = gm_send_msg(s, GM_PUSH_MANIFEST, enc, (uint32_t)n);
    free(enc);
    if (rc != 0) {
        gm_close(s);
        gm_die("connection lost");
    }

    uint8_t type = 0;
    uint8_t *payload = NULL;
    uint32_t len = 0;
    if (gm_recv_msg(s, &type, &payload, &len) != 0 || type != GM_SYNC_PLAN) {
        gm_close(s);
        gm_die("peer did not accept manifest");
    }
    gm_plan plan;
    if (parse_plan(payload, len, &plan) != 0) {
        free(payload);
        gm_close(s);
        gm_die("bad plan from peer");
    }
    free(payload);

    for (size_t i = 0; i < plan.n_conflict; i++)
        fprintf(stderr, "conflict (skipped): %s\n", plan.conflict[i]);
    printf("%zu file(s) to transfer\n\n", plan.n_want);

    for (size_t i = 0; i < plan.n_want && rc == 0; i++) {
        uint32_t idx = plan.want[i];
        if (idx >= cur.n) {
            rc = -1;
            break;
        }
        rc = send_file(s, root, cur.v[idx].path, cur.v[idx].hash);
    }
    if (rc == 0)
        rc = gm_send_msg(s, GM_DONE, "", 0);
    if (rc == 0 && gm_recv_msg(s, &type, &payload, &len) == 0 &&
        type == GM_DONE) {
        printf("peer: %.*s\n", (int)(len > 100 ? 100 : len), (const char *)payload);
        free(payload);
        gm_index_save(root, &cur);
    } else if (rc == 0) {
        fprintf(stderr, "transfer incomplete\n");
    }
    plan_free(&plan);
    gm_close(s);
    gm_manifest_free(&old);
    gm_manifest_free(&cur);
    return rc == 0 ? 0 : 1;
}

int gm_cmd_receive(const char *peer) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    gm_sock_init();
    gm_ident id;
    gm_ident_load(&id);
    char ip[48];
    uint16_t port = gm_env_tcp_port();
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    resolve_or_die(&id, peer, ip, &port, pk);
    if (pk[0] || pk[1]) {
        if (!gm_known_check(pk)) gm_known_pin(NULL, pk, peer);
    }

    char root[GM_PATH_MAX];
    project_root(root, sizeof root);

    printf("\nconnecting %s (%s:%u)\n", peer, ip, port);
    gm_sess *s = gm_connect(ip, port);
    {
        const uint8_t *spk = gm_sess_peer_pk(s);
        if (!gm_known_check(spk)) gm_known_pin(NULL, spk, peer);
    }
    if (gm_send_msg(s, GM_GET_MANIFEST, "", 0) != 0) {
        gm_close(s);
        gm_die("connection lost");
    }

    uint8_t type = 0;
    uint8_t *payload = NULL;
    uint32_t len = 0;
    if (gm_recv_msg(s, &type, &payload, &len) != 0 || type != GM_MANIFEST) {
        gm_close(s);
        gm_die("could not fetch peer manifest");
    }
    gm_manifest theirs = {0};
    if (manifest_decode(payload, len, &theirs) != 0) {
        free(payload);
        gm_close(s);
        gm_die("bad manifest from peer");
    }
    free(payload);

    gm_manifest old = {0}, mine = {0};
    gm_index_load(root, &old);
    gm_scan(root, &old, &mine);
    gm_plan plan;
    plan_compute(&theirs, &mine, &old, &plan);

    size_t adds = 0;
    for (size_t i = 0; i < plan.n_want; i++) {
        uint32_t wi = plan.want[i];
        if (wi < theirs.n && !gm_manifest_find(&mine, theirs.v[wi].path))
            adds++;
    }
    printf("\n%zu file(s) to add/update\n%zu new file(s)\n%zu deletion(s)\n",
           plan.n_want, adds, plan.n_del);
    for (size_t i = 0; i < plan.n_conflict; i++)
        fprintf(stderr, "conflict (kept local): %s\n", plan.conflict[i]);
    if (plan.n_want == 0 && plan.n_del == 0) {
        printf("already up to date\n");
        plan_free(&plan);
        gm_manifest_free(&theirs);
        gm_manifest_free(&old);
        gm_manifest_free(&mine);
        gm_close(s);
        return 0;
    }
    if (!confirm("apply changes from peer?")) {
        printf("aborted\n");
        plan_free(&plan);
        gm_manifest_free(&theirs);
        gm_manifest_free(&old);
        gm_manifest_free(&mine);
        gm_close(s);
        return 1;
    }

    size_t n = 4 + plan.n_want * 4;
    uint8_t *buf = gm_xmalloc(n);
    uint32_t w = (uint32_t)plan.n_want;
    memcpy(buf, &w, 4);
    for (size_t i = 0; i < plan.n_want; i++)
        memcpy(buf + 4 + i * 4, &plan.want[i], 4);
    int rc = gm_send_msg(s, GM_WANT, buf, (uint32_t)(4 + plan.n_want * 4));
    free(buf);

    gm_manifest applied = {0};
    if (rc == 0)
        rc = recv_files(s, root, &applied);
    if (rc == 0) {
        apply_deletes(root, &plan, &old);
        merge_index(&old, &applied);
        gm_index_save(root, &old);
        printf("done: %zu applied\n", applied.n);
    } else {
        fprintf(stderr, "transfer incomplete\n");
    }
    plan_free(&plan);
    gm_manifest_free(&theirs);
    gm_manifest_free(&old);
    gm_manifest_free(&mine);
    gm_manifest_free(&applied);
    gm_close(s);
    return rc == 0 ? 0 : 1;
}
