#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lz4.h>

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
            wire = 5 + (uint32_t)chunk;
            payload = gm_xmalloc(wire);
            payload[0] = 0;
            memcpy(payload + 1, buf, chunk);
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
