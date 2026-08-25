#include "gitmesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void gm_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void *gm_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) gm_die("out of memory");
    return p;
}

void *gm_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) gm_die("out of memory");
    return q;
}

char *gm_xstrdup(const char *s) {
    char *d = strdup(s);
    if (!d) gm_die("out of memory");
    return d;
}

static const char HEXD[] = "0123456789abcdef";

void gm_hex(char *out, const uint8_t *in, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = HEXD[in[i] >> 4];
        out[i * 2 + 1] = HEXD[in[i] & 15];
    }
    out[n * 2] = 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int gm_unhex(uint8_t *out, size_t outn, const char *in) {
    if (strlen(in) != outn * 2) return -1;
    for (size_t i = 0; i < outn; i++) {
        int hi = hexval(in[i * 2]), lo = hexval(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

int gm_home_path(char *buf, size_t n, const char *rel) {
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (!home || !*home) home = getenv("USERPROFILE");
#endif
    if (!home || !*home) return -1;
    if (!rel) rel = "";
    int r = snprintf(buf, n, "%s/.gitmesh%s%s", home, *rel ? "/" : "", rel);
    return r >= 0 && (size_t)r < n ? 0 : -1;
}

void gm_gethostname(char *buf, size_t n) {
    if (gethostname(buf, n) != 0) snprintf(buf, n, "unnamed");
    buf[n - 1] = 0;
}

int64_t gm_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int gm_read_file(const char *path, uint8_t **out, size_t *outn) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    uint8_t *buf = gm_xmalloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return -1; }
    buf[sz] = 0;
    *out = buf;
    *outn = (size_t)sz;
    return 0;
}

static void ensure_parents(char *path) {
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(path, 0755);
            *p = '/';
        }
    }
}

int gm_write_file_atomic(const char *root, const char *rel, const uint8_t *data, size_t n) {
    char final_path[GM_PATH_MAX], tmp_path[GM_PATH_MAX];
    if (snprintf(final_path, sizeof final_path, "%s/%s", root, rel) >= (int)sizeof final_path)
        return -1;
    ensure_parents(final_path);
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp%lx", final_path, (unsigned long)getpid()) >= (int)sizeof tmp_path)
        return -1;
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, data + off, n - off);
        if (w <= 0) { close(fd); unlink(tmp_path); return -1; }
        off += (size_t)w;
    }
    if (close(fd) != 0 || rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}
