#ifndef GM_PLATFORM_H
#define GM_PLATFORM_H

#if defined(_WIN32)
#include "platforms/win32/platform.h"
#elif defined(__APPLE__)
#include "platforms/darwin/platform.h"
#else
#include "platforms/linux/platform.h"
#endif

#endif
