#ifndef GM_PLATFORM_WIN32_H
#define GM_PLATFORM_WIN32_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>

#define GM_HAVE_REUSEPORT 0

typedef int socklen_t;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define mkdir(p, m) _mkdir(p)

static inline int64_t gm_st_mtime_ms(const struct stat *st) {
    return (int64_t)st->st_mtime * 1000;
}

static inline int gm_sock_init(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

static inline int gm_sock_close(SOCKET fd) { return closesocket(fd); }

#endif
