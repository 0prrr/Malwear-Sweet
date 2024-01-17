#include "syscall.h"

#define INITIAL_SEED 8

DWORD jenkins(_In_ PCHAR String)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

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

BOOL resolve_nt_syscall(_In_ DWORD dw_syscall_hash, _Out_ PNT_SYSCALL pNtSys)
{
    if (NULL != dw_syscall_hash)
        pNtSys->dw_nt_func_hash = dw_syscall_hash;
    else
        return FALSE;

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    PLDR_DATA_TABLE_ENTRY p_ldr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    ULONG_PTR ul_base_addr = (ULONG_PTR)(p_ldr->DllBase);
    if (!ul_base_addr)
        return FALSE;

    PIMAGE_DOS_HEADER p_dos_hdr = (PIMAGE_DOS_HEADER)ul_base_addr;
    if (p_dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)(ul_base_addr + p_dos_hdr->e_lfanew);
    if (p_nt_hdr->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY p_exp_dir = (PIMAGE_EXPORT_DIRECTORY)(ul_base_addr + p_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!p_exp_dir)
        return FALSE;

    DWORD dw_num_name = p_exp_dir->NumberOfNames;
    PDWORD pdw_arr_name = (PDWORD)(ul_base_addr + p_exp_dir->AddressOfNames);
    PDWORD pdw_arr_addr = (PDWORD)(ul_base_addr + p_exp_dir->AddressOfFunctions);
    PWORD pw_arr_ord = (PWORD)(ul_base_addr + p_exp_dir->AddressOfNameOrdinals);

    for (size_t i = 0; i < dw_num_name; i++)
    {
        PCHAR pcFuncName = (PCHAR)(ul_base_addr + pdw_arr_name[i]);
        PVOID pFuncAddress = (PVOID)(ul_base_addr + pdw_arr_addr[pw_arr_ord[i]]);

        // if syscall found
        if (_HASH(pcFuncName) == dw_syscall_hash)
        {
            pNtSys->p_nt_func_addr = pFuncAddress;

            for (DWORD z = 0, x = 1; z <= 0x20; z++, x++)
            {
                if (0x0F == *((PBYTE)pFuncAddress + z) && 0x05 == *((PBYTE)pFuncAddress + x))
                {
                    // the address of syscall; ret instruction for each Nt API
                    pNtSys->p_syscall_inst_addr = ((ULONG_PTR)pFuncAddress + z);
                    break; // break for-loop [x & z]
                }
            }

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00)
            {
                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dw_ssn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == 0xE9)
            {
                for (WORD idx = 1; idx <= _RANGE; idx++)
                {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * _DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * _DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * _DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * _DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * _DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * _DOWN) == 0x00)
                    {
                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * _DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * _DOWN);
                        pNtSys->dw_ssn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * _UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * _UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * _UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * _UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * _UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * _UP) == 0x00)
                    {
                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * _UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * _UP);
                        pNtSys->dw_ssn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == 0xE9)
            {
                for (WORD idx = 1; idx <= _RANGE; idx++)
                {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * _DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * _DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * _DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * _DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * _DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * _DOWN) == 0x00)
                    {
                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * _DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * _DOWN);
                        pNtSys->dw_ssn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * _UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * _UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * _UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * _UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * _UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * _UP) == 0x00)
                    {
                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * _UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * _UP);
                        pNtSys->dw_ssn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }
    }

    if (NULL != pNtSys->dw_ssn && NULL != pNtSys->p_nt_func_addr && NULL != pNtSys->dw_nt_func_hash && NULL != pNtSys->p_syscall_inst_addr)
        return TRUE;
    else
        return FALSE;
}

