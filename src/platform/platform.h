#ifndef GM_PLATFORM_H
#define GM_PLATFORM_H

#if defined(_WIN32)
#include "../win32/platform.h"
#elif defined(__APPLE__)
#include "../darwin/platform.h"
#else
#include "../linux/platform.h"
#endif

#endif
