#ifndef GM_PLATFORM_DARWIN_H
#define GM_PLATFORM_DARWIN_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ifaddrs.h>

#define GM_HAVE_REUSEPORT 1

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static inline int64_t gm_st_mtime_ms(const struct stat *st) {
    return (int64_t)st->st_mtimespec.tv_sec * 1000 + st->st_mtimespec.tv_nsec / 1000000;
}

static inline int gm_sock_init(void) { return 0; }
static inline int gm_sock_close(int fd) { return close(fd); }

#endif
