#include <Windows.h>
#include "Common.h"

HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash)
{
	if (NULL == dwModuleNameHash) return NULL;

#ifdef _WIN64
	PPEB pPEB = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB pPEB = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPEB->LoaderData);
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDataTableEntry)
	{
		if (NULL != pDataTableEntry->FullDllName.Length && pDataTableEntry->FullDllName.Length < MAX_PATH)
		{
			CHAR UpperCaseDLLName[MAX_PATH];

			DWORD i = 0;

			while (pDataTableEntry->FullDllName.Buffer[i])
			{
				UpperCaseDLLName[i] = (CHAR)toupper(pDataTableEntry->FullDllName.Buffer[i]);
				i++;
			}

			UpperCaseDLLName[i] = '\0';

			// check if equal to target module name
			if (dwModuleNameHash == HASH(UpperCaseDLLName))
			{
				return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
			}
		}
		else break;

		// Get next element in the linked list
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

	if (0 == EatVirtualAddress) return NULL;

	pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + EatVirtualAddress);

	FunctionNameArray = (PDWORD)(pBase + pImgExpDir->AddressOfNames);
	pFunctionAddressesArray = (PDWORD)(pBase + pImgExpDir->AddressOfFunctions);
	FunctionOrdinalArray = (PWORD)(pBase + pImgExpDir->AddressOfNameOrdinals);

	NmbrOfFunctions = pImgExpDir->NumberOfFunctions;

	if (0 == NmbrOfFunctions) return NULL;

	for (DWORD i = 0; i < NmbrOfFunctions; i++)
	{
		pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		pFunctionAddress = (PVOID)(pBase + pFunctionAddressesArray[FunctionOrdinalArray[i]]);

		if (dwAPINameHash == HASH(pFunctionName))
			return pFunctionAddress;
	}

	return NULL;
}

