#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

void gm_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void *gm_xmalloc(size_t n) {
    void *ptr = malloc(n ? n : 1);
    if (!ptr) gm_die("out of memory");
    return ptr;
}

void *gm_xrealloc(void *p, size_t n) {
    void *resized = realloc(p, n ? n : 1);
    if (!resized) gm_die("out of memory");
    return resized;
}

char *gm_xstrdup(const char *s) {
    char *copy = strdup(s);
    if (!copy) gm_die("out of memory");
    return copy;
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
        int high_nibble = hexval(in[i * 2]), low_nibble = hexval(in[i * 2 + 1]);
        if (high_nibble < 0 || low_nibble < 0) return -1;
        out[i] = (uint8_t)(high_nibble << 4 | low_nibble);
    }
    return 0;
}

int gm_home_path(char *buf, size_t n, const char *rel) {
    const char *home_dir = getenv("HOME");
#ifdef _WIN32
    if (!home_dir || !*home_dir) home_dir = getenv("USERPROFILE");
#endif
    if (!home_dir || !*home_dir) return -1;
    if (!rel) rel = "";
    int printed = snprintf(buf, n, "%s/.gitmesh%s%s", home_dir, *rel ? "/" : "", rel);
    return printed >= 0 && (size_t)printed < n ? 0 : -1;
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
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (file_size < 0) { fclose(file); return -1; }
    uint8_t *buf = gm_xmalloc((size_t)file_size + 1);
    size_t bytes_read = fread(buf, 1, (size_t)file_size, file);
    fclose(file);
    if (bytes_read != (size_t)file_size) { free(buf); return -1; }
    buf[file_size] = 0;
    *out = buf;
    *outn = (size_t)file_size;
    return 0;
}

static void ensure_parents(char *path) {
    for (char *cursor = path + 1; *cursor; cursor++) {
        if (*cursor == '/') {
            *cursor = 0;
            mkdir(path, 0755);
            *cursor = '/';
        }
    }
}

int gm_write_file_atomic(const char *root, const char *rel, const uint8_t *data, size_t n) {
    char final_path[GM_PATH_MAX];
    char tmp_path[GM_PATH_MAX];
    if (snprintf(final_path, sizeof final_path, "%s/%s", root, rel) >= (int)sizeof final_path)
        return -1;
    ensure_parents(final_path);
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp%lx", final_path, (unsigned long)getpid()) >= (int)sizeof tmp_path)
        return -1;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0644);
    if (fd < 0) return -1;

    size_t offset = 0;
    while (offset < n) {
        ssize_t bytes_written = write(fd, data + offset, n - offset);
        if (bytes_written <= 0) { close(fd); unlink(tmp_path); return -1; }
        offset += (size_t)bytes_written;
    }

    if (close(fd) != 0 || rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}
