#include "pebwalking.h"

char to_upper(_In_ char c)
{
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 'A';

    return c;
}

size_t cstrlenA(const char* _str)
{
    size_t length = 0;
    while (*_str++)
        length++;

    return length;
}

#pragma intrinsic(strrchr)
#pragma function(strrchr)
// char* strrchr(const char* str, int c) {
_CONST_RETURN char *__cdecl strrchr(const char *str, int c)
{
    char* last_occurrence = NULL;
    while (*str)
    {
        if (*str == c)
            last_occurrence = (char*)str;
        str++;
    }

    return last_occurrence;
}

// NOTE: Here Dll name must be uppercase for hashing
HMODULE get_mod_hndl_by_hash(_In_ DWORD dw_mod_name_hash)
{
    PPEB p_peb = (PEB*)(__readgsqword(0x60));

    PPEB_LDR_DATA p_ldr = (PPEB_LDR_DATA)(p_peb->LoaderData);
    PLDR_DATA_TABLE_ENTRY p_dte = (PLDR_DATA_TABLE_ENTRY)(((unsigned char*)p_ldr->InMemoryOrderModuleList.Flink) - 0x10);

    if (NULL == dw_mod_name_hash)
        return (HMODULE)(p_dte->InInitializationOrderLinks.Flink);

    while (p_dte)
    {
        if (p_dte->BaseDllName.Buffer && p_dte->BaseDllName.Length)
        {
            wchar_t upcase_dll_name[MAX_PATH];
            size_t i = 0;
            while (p_dte->BaseDllName.Buffer[i])
            {
                upcase_dll_name[i] = (wchar_t)to_upper(p_dte->BaseDllName.Buffer[i]);
                i++;
            }
            upcase_dll_name[i] = 0;
            // check if equal to target module name
            if (dw_mod_name_hash == _HASHW(upcase_dll_name))
                return p_dte->DllBase;
        }
        else
            break;

        p_dte = *(PLDR_DATA_TABLE_ENTRY*)(p_dte);
    }

    return NULL;
}

FARPROC get_proc_addr_by_hash(_In_ HMODULE h_mod, _In_ DWORD dw_proc_hash)
{
    if (NULL == h_mod || NULL == dw_proc_hash)
        return NULL;

    // function address we're looking for
    PCHAR p_proc_addr = NULL;

    PBYTE p_base = (PBYTE)h_mod;
    PIMAGE_NT_HEADERS p_nt_hdrs = NULL;
    PIMAGE_EXPORT_DIRECTORY p_exp_data_dir = NULL;
    PDWORD pdw_func_name_arr = NULL;
    PDWORD pdw_func_addr_arr = NULL;
    PWORD pw_func_ord_arr = NULL;
    DWORD dw_exp_dir_size = 0x0;

    p_nt_hdrs = (PIMAGE_NT_HEADERS)(p_base + ((PIMAGE_DOS_HEADER)p_base)->e_lfanew);
    if (p_nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    p_exp_data_dir = (PIMAGE_EXPORT_DIRECTORY)(p_base + p_nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    dw_exp_dir_size = p_nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    pdw_func_name_arr = (PDWORD)(p_base + p_exp_data_dir->AddressOfNames);
    pdw_func_addr_arr = (PDWORD)(p_base + p_exp_data_dir->AddressOfFunctions);
    pw_func_ord_arr = (PWORD)(p_base + p_exp_data_dir->AddressOfNameOrdinals);

    // resolve function by ordinal
    if (0 == ((ULONG_PTR)dw_proc_hash >> 16))
    {
        WORD ordinal = (WORD)dw_proc_hash & 0xFFFF;         // convert to WORD
        DWORD Base = p_exp_data_dir->Base;                  // first ordinal number

        // check if ordinal is not out of scope
        if (ordinal < Base || ordinal >= Base + p_exp_data_dir->NumberOfFunctions)
            return NULL;

        // get the function virtual address = RVA + BaseAddr
        p_proc_addr = (p_base + (DWORD_PTR)pdw_func_addr_arr[ordinal - Base]);
    }
    else
    {
        // resolve function by name
        // parse through table of function names
        for (DWORD i = 0; i < p_exp_data_dir->NumberOfNames; i++)
        {
            PCHAR p_func_name = (PCHAR)(p_base + pdw_func_name_arr[i]);

            if (dw_proc_hash == _HASHA(p_func_name))
            {
                p_proc_addr = (PVOID)(p_base + pdw_func_addr_arr[pw_func_ord_arr[i]]);
                break;
            }
        }
    }

    // check if found VA is forwarded to external library.function
    if ((PCHAR)p_proc_addr >= (PCHAR)p_exp_data_dir &&
        (PCHAR)p_proc_addr < ((PCHAR)(p_exp_data_dir) + dw_exp_dir_size))
    {
        CHAR c_fwd_dll[MAX_PATH] = { 0 };
        memcpy(c_fwd_dll, p_proc_addr, cstrlenA((PCHAR)p_proc_addr));

        // get external function name
        PCHAR p_fwd_func = strrchr(c_fwd_dll, '.');
        *p_fwd_func = 0;      // set trailing null byte for external library name -> library\x0function
        p_fwd_func++;         // shift a pointer to the beginning of function name

        // load the external library
        HMODULE h_mod_fwd = g_win_api_tbl.LoadLibraryA(c_fwd_dll);
        if (!h_mod_fwd)
            return NULL;

        // get the address of function the original call is forwarded to
        p_proc_addr = get_proc_addr_by_hash(h_mod_fwd, _HASHA(p_fwd_func));
    }

    return (FARPROC)p_proc_addr;
}

