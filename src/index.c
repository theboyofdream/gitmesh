#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *IGNORE_NAMES[] = {
    ".git", ".gitmesh", "node_modules", "target", "dist",
    "build", "__pycache__", ".DS_Store", NULL,
};

static const char *IGNORE_SUFFIX[] = {".pyc", NULL};

static bool ignored(const char *name) {
    for (int i = 0; IGNORE_NAMES[i]; i++)
        if (strcmp(name, IGNORE_NAMES[i]) == 0) return true;
    for (int i = 0; IGNORE_SUFFIX[i]; i++) {
        size_t nl = strlen(name), sl = strlen(IGNORE_SUFFIX[i]);
        if (nl >= sl && strcmp(name + nl - sl, IGNORE_SUFFIX[i]) == 0) return true;
    }
    return false;
}

void gm_manifest_free(gm_manifest *m) {
    for (size_t i = 0; i < m->n; i++) free(m->v[i].path);
    free(m->v);
    m->v = NULL;
    m->n = m->cap = 0;
}

static gm_entry *manifest_push(gm_manifest *m) {
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 64;
        m->v = gm_xrealloc(m->v, m->cap * sizeof *m->v);
    }
    return &m->v[m->n++];
}

static int cmp_entry(const void *a, const void *b) {
    return strcmp(((const gm_entry *)a)->path, ((const gm_entry *)b)->path);
}

void gm_manifest_sort(gm_manifest *m) {
    qsort(m->v, m->n, sizeof *m->v, cmp_entry);
}

static gm_entry *find_entry(const gm_manifest *m, const char *path) {
    size_t lo = 0, hi = m->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(m->v[mid].path, path);
        if (c == 0) return &m->v[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

static int hash_file(const char *full, uint8_t out[crypto_generichash_BYTES]) {
    FILE *f = fopen(full, "rb");
    if (!f) return -1;
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, crypto_generichash_BYTES);
    static _Thread_local uint8_t buf[GM_CHUNK];
    size_t r;
    while ((r = fread(buf, 1, sizeof buf, f)) > 0)
        crypto_generichash_update(&st, buf, r);
    fclose(f);
    crypto_generichash_final(&st, out, crypto_generichash_BYTES);
    return 0;
}

static void scan_dir(const char *root, const char *rel, const gm_manifest *old, gm_manifest *out) {
    char full[GM_PATH_MAX];
    snprintf(full, sizeof full, "%s/%s", root, rel[0] ? rel : ".");
    DIR *d = opendir(full);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (ignored(de->d_name)) continue;
        char crel[GM_PATH_MAX], cfull[GM_PATH_MAX];
        snprintf(crel, sizeof crel, "%s%s%s", rel, rel[0] ? "/" : "", de->d_name);
        if (snprintf(cfull, sizeof cfull, "%s/%s", root, crel) >= (int)sizeof cfull) continue;

        struct stat st;
#ifndef _WIN32
        if (lstat(cfull, &st) != 0 || S_ISLNK(st.st_mode)) continue;
#else
        if (stat(cfull, &st) != 0) continue;
#endif
        if (S_ISDIR(st.st_mode)) {
            scan_dir(root, crel, old, out);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        gm_entry *old_e = find_entry(old, crel);
        gm_entry e = {0};
        e.path = gm_xstrdup(crel);
        e.size = (uint64_t)st.st_size;
        e.mtime = gm_st_mtime_ms(&st);
        if (old_e && old_e->size == e.size && old_e->mtime == e.mtime) {
            memcpy(e.hash, old_e->hash, sizeof e.hash);
        } else if (hash_file(cfull, e.hash) != 0) {
            free(e.path);
            continue;
        }
        *manifest_push(out) = e;
    }
    closedir(d);
}

int gm_scan(const char *root, const gm_manifest *old, gm_manifest *out) {
    memset(out, 0, sizeof *out);
    scan_dir(root, "", old, out);
    gm_manifest_sort(out);
    return 0;
}

int gm_index_load(const char *root, gm_manifest *m) {
    memset(m, 0, sizeof *m);
    char path[GM_PATH_MAX];
    snprintf(path, sizeof path, "%s/.gitmesh/index", root);
    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(path, &data, &n) != 0) return -1;
    if (n < 4) { free(data); return -1; }
    uint32_t count;
    memcpy(&count, data, 4);
    size_t off = 4;
    for (uint32_t i = 0; i < count && off + 2 <= n; i++) {
        uint16_t plen;
        memcpy(&plen, data + off, 2);
        off += 2;
        if (off + (size_t)plen + crypto_generichash_BYTES + 8 + 8 > n) break;
        gm_entry *e = manifest_push(m);
        e->path = gm_xmalloc((size_t)plen + 1);
        memcpy(e->path, data + off, plen);
        e->path[plen] = 0;
        off += plen;
        memcpy(e->hash, data + off, crypto_generichash_BYTES);
        off += crypto_generichash_BYTES;
        memcpy(&e->size, data + off, 8);
        off += 8;
        memcpy(&e->mtime, data + off, 8);
        off += 8;
    }
    free(data);
    gm_manifest_sort(m);
    return 0;
}

int gm_index_save(const char *root, const gm_manifest *m) {
    size_t n = 4;
    for (size_t i = 0; i < m->n; i++)
        n += 2 + strlen(m->v[i].path) + crypto_generichash_BYTES + 16;
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
        memcpy(buf + off, &m->v[i].mtime, 8);
        off += 8;
    }
    int rc = gm_write_file_atomic(root, ".gitmesh/index", buf, off);
    free(buf);
    return rc;
}

void gm_diff(const gm_manifest *old, const gm_manifest *cur,
             size_t *added, size_t *modified, size_t *deleted) {
    *added = *modified = *deleted = 0;
    size_t i = 0, j = 0;
    while (i < old->n && j < cur->n) {
        int c = strcmp(old->v[i].path, cur->v[j].path);
        if (c < 0) { (*deleted)++; i++; }
        else if (c > 0) { (*added)++; j++; }
        else {
            if (memcmp(old->v[i].hash, cur->v[j].hash, crypto_generichash_BYTES) != 0)
                (*modified)++;
            i++;
            j++;
        }
    }
    *deleted += old->n - i;
    *added += cur->n - j;
}
