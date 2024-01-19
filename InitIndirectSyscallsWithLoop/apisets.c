/*
 * Change apisets.h and this file for API changes
 *
 */

#include "apisets.h"

// Append API to MAL_NT_API_TBL in apisets.c
// Append API to mal_nt_hash_arr
// Append API to mal_nt_name_arr
// !!! NOTE THAT ORDER MUST MATCH !!!
const DWORD mal_nt_hash_arr[] = {
    0x837FAFFE,     // NtOpenProcess
    0x71D40BAA,     // NtQueryInformationProcess
    0x192C02CE,     // NtCreateSection
    0x91436663,     // NtMapViewOfSection
    0x0A5B9402,     // NtUnmapViewOfSection
    0x8EC0B84A,     // NtCreateThreadEx
    0xEB15EA8A,     // NtQueueApcThread
    0x91527655,     // NtAlertResumeThread
    0xB947891A,     // NtDelayExecution
    0x6299AD3D,     // NtWaitForSingleObject
    0x369BD981      // NtClose
};

// !!! NOTE THAT ORDER MUST MATCH !!!
const DWORD win_api_hash_arr[] = {
    0x54C1D227,     // LoadLibraryA
    0x1E73D3C6,     // AddVectoredExceptionHandler
    0xE35AA59E,     // RemoveVectoredExceptionHandler
    0x64D58672,     // CreateTimerQueue
    0x1206428D,     // CreateTimerQueueTimer
    0x78C9046C,     // RtlAddFunctionTable
    0xB7DEBBF2,     // InitializeCriticalSection
    0xEE965B0B,     // EnterCriticalSection
    0x4E34D319      // LeaveCriticalSection
};

const DWORD win_dll_hash_arr[] = {
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
    0xFD2AD9BD,     // KERNEL32
};

#ifdef _DEBUG

const PCHAR mal_nt_name_arr[] = {
    "NtOpenProcess",
    "NtQueryInformationProcess",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtAlertResumeThread",
    "NtDelayExecution",
    "NtWaitForSingleObject",
    "NtClose"
};

const PCHAR win_api_name_arr[] = {
    "LoadLibraryA",
    "AddVectoredExceptionHandler",
    "RemoveVectoredExceptionHandler",
    "CreateTimerQueue",
    "CreateTimerQueueTimer",
    "RtlAddFunctionTable",
    "InitializeCriticalSection",
    "EnterCriticalSection",
    "LeaveCriticalSection"
};

#endif

