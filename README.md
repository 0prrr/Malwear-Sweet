# Malwear-Sweet

Please kindly compile all projects in RELEASE mode.

* SilenBishop

	Reimplementation of b33f's UrbanBishop with syscall. [FuzzySecurity/Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/UrbanBishop/UrbanBishop.sln) @b33f. MalDevAcademy @mrd0x @NUL0x4C
	
* BootExecuteNativeApp

	Native application for BootExecute/SetupExecute key persistence test. No MSVCRT, soley rely on ntdll.dll. Clone the repo. add the project by "Open a project or solution", and select the `.vcxproj` file.

	References:
	<br/>https://renenyffenegger.ch/notes/Windows/development/native-applications/index
	<br/>https://stackoverflow.com/questions/10164724/windows-registry-how-to-add-your-native-program-for-boot-executing

* TheLostThread

    Hijack a thread without calling SetThreadContext. Still needs improvement because I'm lazy and haven't implement the whole thing well enough to maintain the original functionality of the thread. Just a quick and dirty PoC. Tested on Windows version 1809 (chrome.exe, msedge.exe, notepad.exe), 22H2 (chrome.exe, msedge.exe, notepad.exe), Windows 11 22H2 (chrome.exe, firefox.exe, msedge.exe, notepad.exe). Be ware of payload execution control. Browsers tend to execute the payload multiple times.

* RopLegit

    Since `jmp rcx` gadget is subject to CFG bitmap contrl. This is sort of a work around to use `jmp rdx` gadget and a `CREATE_SUSPENDED` thread to get code execution. But, it's not that 'effective' since you have to take into consideration too many things (register thingy...), the process will crash. Just a work around like I said.

* RopCfgFree

    This is the ultimate go if ever have to use a ROP gadget. A gadget in `bcyrpt.dll` can be used to bypass CFG and get code execution theoretically on any process that has `bcrypt.dll` loaded. Tested on windows 1809, 1909 (chances of failure, reason unknown yet), 21H1, 22H2, windows 11 22H2. Note that once `SetProcessValidCallTargets` is successful, and the process remains alive, CFG on that specifc address is always disabled. Have fun!

* ThreadlessInjection
    
    Code ported from [CCob and rasta-mouse's threadless injection](https://github.com/CCob/ThreadlessInject/tree/master). Tested on Windows version 1809 (explorer.exe, chrome.exe, firefox.exe, notepad.exe), 1909 (explorer.exe, chrome.exe, msedge.exe, notepad.exe), 21H1 (explorer.exe, chrome.exe, msedge.exe, notepad.exe), 22H2 (explorer.exe, chrome.exe, msedge.exe, notepad.exe), Win11 22H2 (explorer.exe, chrome.exe, msedge.exe, firefox.exe, notepad.exe). CreateEventW is enough to trigger on all tested processes. Please add your own shellcode encryption. Feel free to add other techniques.

* COMShellExecute
    
    Use `ShellExecute` method exposed by COM object `13709620-C279-11CE-A49E-444553540000` to execute command in C. Nothing interesting, just for fun and stuff.

* ProcessHollowing (Not quite)
    
    Code for process "hollowing" and hopefully more variants in the future. Not quite hollowing the target process since unbacked memory is more like an IoC. The code plays around remote entry point. Good practice for understanding PEB and PE header a bit more.

    [*] ProcessHollowing_1

  	Write shellcode to host process's entry point, then resume host thread. Host process: `svchost.exe`.

    [*] ProcessHollowing_2

  	Write PE to host process's memory region. Patch host process's entry point to jump to our PE's entry point, then resume host thread. Host process: `RuntimeBroker.exe`.

    [*] ProcessHollowing_3

  	Write PE to host process's memory region. Hijack host process's RCX register (which points to entry point), then resume host thread. Host process: `Werfault.exe`.

    [*] ProcessHollowing_4

  	Read PE from disk (or resources), patch ImageBase, IAT, relocations locally (don't have to read host process info after writing the PE anymore), write patched PE to host process, hijack host process's RCX register, then resume host thread. Now, we can handle more complex PEs which have a lot of imports and relocations, and of course simpler PEs like our shellcode runner should be running as intended. Tested with `putty.exe` on Windows version 1809, 1909, 21H1, 22H2, Windows 11 version 22H2.

    References:
    <br/>https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf
    <br/>https://dione.lib.unipi.gr/xmlui/bitstream/handle/unipi/11578/Balaoura_MTE1623.pdf?sequence=1&isAllowed=y
    <br/>https://github.com/m0n0ph1/Process-Hollowing/blob/master/sourcecode/ProcessHollowing/ProcessHollowing.cpp
    <br/>https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
    <br/>https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations

* DontPutYourEggsInOneBasket
    
    The idea is to drop (modularized) shellcdoe into different memory regions (different process???), each part (call it stage) relies on its own and completes certain functionality like resolving functions, setting up registers etc. Then linking each stage together (now by jmp-ing). It seems for now writing your own shellcode is the way to accomplish the goal of staging, since even the basic `exec` payload from msfvenom is jumping and calling into it's own everywhere which makes the goal very hard to reach. I don't know if there's a way to manipulate beacons or more complex paylaods directly, I'm open for discussion.

    The PoC is a handwritten x64 shellcode which resolves `WinExec` and `TerminateProcess` by hash and pops calc.exe. The shellcode will be separated into two stages and linked together by patching the address of second stage into the first one.

    Tested on Windows version 1809, 1909, 21H1, 22H2, Windows 11 22H2. Windows Defender didn't buzz at all.

    Next step will be digging into beacon and reverse shell payloads and learn more about the asm implementation, see what can be harnessed.

    Referneces:
    <br/>OSED Course
    <br/>https://www.bordergate.co.uk/windows-x64-shellcode-development/
    <br/>https://www.aldeid.com/wiki/PE-Portable-executable
    <br/>https://www.aldeid.com/wiki/PE-Portable-executable#Export_Table
    <br/>https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
    <br/>https://defuse.ca/online-x86-assembler.htm

* CustomShellcode

    Custom written shellcode with Windows `WSA` socket APIs and `CreateProcess`. Furture attempts of handcrafted shellcodes will be added here. Tested on Windows 10 1809, 1909, 21H1, 22H2, Windows 11 22H2.

    References:
    <br/>OSED Course

* SharedMemoryInjection

    Inject DLL into target process which will open a file mapping object and we inject shellcode into that memroy region. The region is not mapped yt, but it will be there as long as the process is alive (check with process hacker, etc...). That being said, explorer might be the best option.

    Then, any process can enumerate that "Section" object, map it, read the shellcode from it, then execute. Just some idea after watching Pavel Yosifovich's video. Check references for the video link. Tested on Windows version 1809, 1909, 21H1, 22H2, Windows 11 22H2.

    References:
    <br/>https://www.youtube.com/watch?v=zdZdtg1f9lA&t=776s

* MetTheStager

    Manual stager for meterpreter reverse tcp in C. You won't believe that it's less than 80 lines of code with socket and one "magic" byte. In a nutshell, the code uses socket to first get a DWORD from remote host, and that's the length of the whole second stage payload. Next, the code allocates a buffer for the second stage according to the length just recieved, but plus 0x5 for the fact that meterpreter needs the socket handle to be in register `rdi` when second stage starts. So, the first 5 bytes of our buffer will be the opcode of instruction `mov edi, 0x11223344`, which will be `\xbf\x44\x33\x22\x11`. `0x11223344` is the place holder for the socket handle. Then, the code fetches the second payload and append it after the first 5 bytes, and executes the whole second stage. That's how a tcp reverse meterpreter payload is staged.

    The benefit is that now we can spawn staged meterpreter shells (with second stage encoded) with this manual stager, and without Windows Defender buzzing. If you use a vanilla stager from msfvenom, Windows Defender will flag the loader when the stager is executed. Meterpreter shell spawned on Windows version 1909, 21H1, 22H2, Windows 11 22H2.

    Other little test results for reference:

    Windows 1909 - cmd shell will be flagged, migrating to other process solves the issue
    WIndows 21H1 - cmd shell, and migrating all flagged
    Windows 22H2 - cmd shell, and migrating all flagged
    Windows 11 22H2 - cmd shell will be flagged, migrating to other process solves the issue

    Next, the code will be converted into custom shellcode in assembly.

    References:
    <br/>https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_reverse_tcp.asm
    <br/>https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c
    <br/>https://github.com/0xdea/tactical-exploitation/blob/master/letme.go

