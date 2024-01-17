/*
*
* Use -D_DEBUG flag when compiling to pass _DEBUG environment variable
* to the code.
*
*/

#pragma once

#ifndef _LOG_H
#define _LOG_H

#include <windows.h>

#ifdef _DEBUG

#define _DLOGW(STR, ...)                                                                    \
    if (1)                                                                                  \
    {                                                                                       \
        LPWSTR buf = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);           \
        if (NULL != buf)                                                                    \
        {                                                                                   \
            int len = wsprintfW(buf, STR, ##__VA_ARGS__);                                   \
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0, buf);                                             \
        }                                                                                   \
    }

#define _DLOGA(STR, ...)                                                                    \
    if (1)                                                                                  \
    {                                                                                       \
        LPSTR buf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);             \
        if (NULL != buf)                                                                    \
        {                                                                                   \
            int len = wsprintfA(buf, STR, ##__VA_ARGS__);                                   \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buf, len, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0, buf);                                             \
        }                                                                                   \
    }

#else

#define _DLOGW(STR, ...)

#define _DLOGA(STR, ...)

#endif // _DEBUG

#endif // !LOG_H

