/*
* 
* Native application for testing persistence in BootExecute registry key
*
*/

#include <Windows.h>
#include "Structs.h"

typedef NTSTATUS(NTAPI* fnNtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

typedef void (WINAPI* pRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

// some functions customly implemented to avoid kernel32.dll
CHAR _toUpper(CHAR C)
{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}

size_t _lstrlenA(const char* lpString)
{
	size_t length = 0;
	while (*lpString++)
		length++;
	return length;
}

size_t _lstrlenW(const wchar_t* lpString)
{
	size_t length = 0;
	while (*lpString++)
		length++;
	return length;
}

UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = _lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = _lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))
#define NTCREATEFILE_HASH 0xCC0911AC
#define RTL_HASH 0x6A83542F
#define NTDLL_HASH 0x4898F593

HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash)
{
	if (NULL == dwModuleNameHash) return NULL;

#ifdef _WIN64
	PPEB pPEB = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB pPEB = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPEB->Ldr);
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDataTableEntry)
	{
		if (NULL != pDataTableEntry->FullDllName.Length && pDataTableEntry->FullDllName.Length < MAX_PATH)
		{
			CHAR UpperCaseDLLName[MAX_PATH];

			DWORD i = 0;

			while (pDataTableEntry->FullDllName.Buffer[i])
			{
				UpperCaseDLLName[i] = (CHAR)_toUpper(pDataTableEntry->FullDllName.Buffer[i]);
				i++;
			}

			UpperCaseDLLName[i] = '\0';

			if (dwModuleNameHash == HASHA(UpperCaseDLLName))
			{
				return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
			}
		}
		else break;

		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
	}

	return NULL;
}

FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwAPINameHash)
{
	if (NULL == hModule || NULL == dwAPINameHash)
		return NULL;

	PBYTE pBase;
	PIMAGE_DOS_HEADER pImgDosHdr;
	PIMAGE_NT_HEADERS pImgNtHdrs;
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	PIMAGE_EXPORT_DIRECTORY pImgExpDir;
	DWORD EatVirtualAddress;
	PDWORD FunctionNameArray;
	PDWORD pFunctionAddressesArray;
	PWORD FunctionOrdinalArray;
	DWORD NmbrOfFunctions;
	CHAR* pFunctionName;
	PVOID pFunctionAddress;

	pBase = (PBYTE)hModule;

	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (IMAGE_DOS_SIGNATURE != pImgDosHdr->e_magic) return NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pImgNtHdrs->Signature) return NULL;

	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	EatVirtualAddress = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (EatVirtualAddress == 0) return NULL;

	pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + EatVirtualAddress);

	FunctionNameArray = (PDWORD)(pBase + pImgExpDir->AddressOfNames);
	pFunctionAddressesArray = (PDWORD)(pBase + pImgExpDir->AddressOfFunctions);
	FunctionOrdinalArray = (PWORD)(pBase + pImgExpDir->AddressOfNameOrdinals);

	NmbrOfFunctions = pImgExpDir->NumberOfFunctions;
	if (NmbrOfFunctions == 0) return NULL;

	for (DWORD i = 0; i < NmbrOfFunctions; i++)
	{
		pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		pFunctionAddress = (PVOID)(pBase + pFunctionAddressesArray[FunctionOrdinalArray[i]]);

		if (dwAPINameHash == HASHA(pFunctionName))
		{
			//printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

// entry point
extern void __stdcall NtProcessStartup(void* Argument)
{
	UNICODE_STRING filePath;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	fnNtCreateFile pfnNtCreateFile = (fnNtCreateFile)GetProcAddressH(GetModuleHandleH(NTDLL_HASH), NTCREATEFILE_HASH);
	pRtlInitUnicodeString pfnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddressH(GetModuleHandleH(NTDLL_HASH), RTL_HASH);

	pfnRtlInitUnicodeString(&filePath, L"\\??\\\\C:\\woohoo.txt");

	InitializeObjectAttributes(&objectAttributes, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = pfnNtCreateFile(&fileHandle, GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);

	return;
}

