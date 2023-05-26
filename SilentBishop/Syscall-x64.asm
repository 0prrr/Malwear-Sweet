.data
	wSystemCall			DWORD	0h	
	qSyscallOpAddr		QWORD	0h	 ; syscall instruction of a benign NT api

.code
	SetSSn PROC	
		xor eax, eax
		mov wSystemCall, eax
		mov qSyscallOpAddr, rax
		mov eax, ecx
		mov wSystemCall, eax
		xor r8, r8
		xchg r8, rdx
		mov qSyscallOpAddr, r8
		ret
	SetSSn ENDP

	ExecSyscall PROC 
		xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSystemCall
		jmp Run
		sar eax, 2
		xor rcx, rcx	
		shl r10, 4
	Run:
		jmp qword ptr [qSyscallOpAddr]
		xor r10, r10
		mov qSyscallOpAddr, r10
		ret
	ExecSyscall ENDP 

end
