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
        size_t name_len = strlen(name), suffix_len = strlen(IGNORE_SUFFIX[i]);
        if (name_len >= suffix_len && strcmp(name + name_len - suffix_len, IGNORE_SUFFIX[i]) == 0) return true;
    }
    return false;
}

void gm_manifest_free(gm_manifest *manifest) {
    for (size_t i = 0; i < manifest->n; i++) free(manifest->v[i].path);
    free(manifest->v);
    manifest->v = NULL;
    manifest->n = manifest->cap = 0;
}

static gm_entry *manifest_push_entry(gm_manifest *manifest) {
    if (manifest->n == manifest->cap) {
        manifest->cap = manifest->cap ? manifest->cap * 2 : 64;
        manifest->v = gm_xrealloc(manifest->v, manifest->cap * sizeof *manifest->v);
    }
    return &manifest->v[manifest->n++];
}

void gm_manifest_push(gm_manifest *manifest, const gm_entry *entry) {
    *manifest_push_entry(manifest) = *entry;
}

static int cmp_entry(const void *a, const void *b) {
    return strcmp(((const gm_entry *)a)->path, ((const gm_entry *)b)->path);
}

void gm_manifest_sort(gm_manifest *manifest) {
    qsort(manifest->v, manifest->n, sizeof *manifest->v, cmp_entry);
}

gm_entry *gm_manifest_find(const gm_manifest *manifest, const char *path) {
    size_t lo = 0;
    size_t hi = manifest->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(manifest->v[mid].path, path);
        if (c == 0) return &manifest->v[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

static int hash_file(const char *file_path, uint8_t out[crypto_generichash_BYTES]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) return -1;
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, crypto_generichash_BYTES);
    static _Thread_local uint8_t buf[GM_CHUNK];
    for (;;) {
        size_t r = 0;
        if (!feof(file) && !ferror(file))
            r = fread(buf, 1, sizeof buf, file);
        if (r == 0) break;
        crypto_generichash_update(&state, buf, r);
    }
    int read_failed = ferror(file) != 0;
    fclose(file);
    if (read_failed) return -1;
    crypto_generichash_final(&state, out, crypto_generichash_BYTES);
    return 0;
}

static void scan_dir(const char *root, const char *rel, const gm_manifest *old, gm_manifest *out) {
    char dir_full[GM_PATH_MAX];
    snprintf(dir_full, sizeof dir_full, "%s/%s", root, rel[0] ? rel : ".");
    DIR *dir = opendir(dir_full);
    if (!dir) return;
    struct dirent *dir_entry;
    while ((dir_entry = readdir(dir))) {
        if (!strcmp(dir_entry->d_name, ".") || !strcmp(dir_entry->d_name, "..")) continue;
        if (ignored(dir_entry->d_name)) continue;
        char child_rel[GM_PATH_MAX];
        char child_full[GM_PATH_MAX];
        snprintf(child_rel, sizeof child_rel, "%s%s%s", rel, rel[0] ? "/" : "", dir_entry->d_name);
        if (snprintf(child_full, sizeof child_full, "%s/%s", root, child_rel) >= (int)sizeof child_full) continue;

        struct stat file_stat;
#ifndef _WIN32
        if (lstat(child_full, &file_stat) != 0 || S_ISLNK(file_stat.st_mode)) continue;
#else
        if (stat(child_full, &file_stat) != 0) continue;
#endif
        if (S_ISDIR(file_stat.st_mode)) {
            scan_dir(root, child_rel, old, out);
            continue;
        }
        if (!S_ISREG(file_stat.st_mode)) continue;

        gm_entry *old_entry = gm_manifest_find(old, child_rel);
        gm_entry entry = {0};
        entry.path = gm_xstrdup(child_rel);
        entry.size = (uint64_t)file_stat.st_size;
        entry.mtime = gm_st_mtime_ms(&file_stat);
        if (old_entry && old_entry->size == entry.size && old_entry->mtime == entry.mtime) {
            memcpy(entry.hash, old_entry->hash, sizeof entry.hash);
        } else if (hash_file(child_full, entry.hash) != 0) {
            free(entry.path);
            continue;
        }
        gm_manifest_push(out, &entry);
    }
    closedir(dir);
}

int gm_scan(const char *root, const gm_manifest *old, gm_manifest *out) {
    memset(out, 0, sizeof *out);
    scan_dir(root, "", old, out);
    gm_manifest_sort(out);
    return 0;
}

int gm_index_load(const char *root, gm_manifest *manifest) {
    memset(manifest, 0, sizeof *manifest);
    char path[GM_PATH_MAX];
    snprintf(path, sizeof path, "%s/.gitmesh/index", root);
    uint8_t *data = NULL;
    size_t n = 0;
    if (gm_read_file(path, &data, &n) != 0) return -1;
    if (n < 4) { free(data); return -1; }
    uint32_t count;
    memcpy(&count, data, 4);
    size_t offset = 4;
    for (uint32_t i = 0; i < count && offset + 2 <= n; i++) {
        uint16_t path_len;
        memcpy(&path_len, data + offset, 2);
        offset += 2;
        if (offset + (size_t)path_len + crypto_generichash_BYTES + 8 + 8 > n) break;
        gm_entry *entry = manifest_push_entry(manifest);
        entry->path = gm_xmalloc((size_t)path_len + 1);
        memcpy(entry->path, data + offset, path_len);
        entry->path[path_len] = 0;
        offset += path_len;
        memcpy(entry->hash, data + offset, crypto_generichash_BYTES);
        offset += crypto_generichash_BYTES;
        memcpy(&entry->size, data + offset, 8);
        offset += 8;
        memcpy(&entry->mtime, data + offset, 8);
        offset += 8;
    }
    free(data);
    gm_manifest_sort(manifest);
    return 0;
}

int gm_index_save(const char *root, const gm_manifest *manifest) {
    size_t n = 4;
    for (size_t i = 0; i < manifest->n; i++)
        n += 2 + strlen(manifest->v[i].path) + crypto_generichash_BYTES + 16;
    uint8_t *buf = gm_xmalloc(n);
    uint32_t count = (uint32_t)manifest->n;
    memcpy(buf, &count, 4);
    size_t offset = 4;
    for (size_t i = 0; i < manifest->n; i++) {
        uint16_t path_len = (uint16_t)strlen(manifest->v[i].path);
        memcpy(buf + offset, &path_len, 2);
        offset += 2;
        memcpy(buf + offset, manifest->v[i].path, path_len);
        offset += path_len;
        memcpy(buf + offset, manifest->v[i].hash, crypto_generichash_BYTES);
        offset += crypto_generichash_BYTES;
        memcpy(buf + offset, &manifest->v[i].size, 8);
        offset += 8;
        memcpy(buf + offset, &manifest->v[i].mtime, 8);
        offset += 8;
    }
    int result = gm_write_file_atomic(root, ".gitmesh/index", buf, offset);
    free(buf);
    return result;
}

void gm_diff(const gm_manifest *old, const gm_manifest *cur,
             size_t *added, size_t *modified, size_t *deleted) {
    *added = *modified = *deleted = 0;
    size_t i = 0;
    size_t j = 0;
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
