# Malwear-Sweet

* SilenBishop

	Reimplementation of b33f's UrbanBishop with syscall
	
* BootExecuteNativeApp

	Native application for BootExecute/SetupExecute key persistence test. No MSVCRT, soley rely on ntdll.dll. Clone the repo. add the project by "Open a project or solution", and select the `.vcxproj` file.

	References:
	<br/>&emsp;&emsp;https://renenyffenegger.ch/notes/Windows/development/native-applications/index
	<br/>&emsp;&emsp;https://stackoverflow.com/questions/10164724/windows-registry-how-to-add-your-native-program-for-boot-executing

* TheLostThread

    Hijack a thread without calling SetThreadContext. Still needs improvement because I'm lazy and haven't implement the whole thing well enough to maintain the original functionality of the thread. Just a quick and dirty PoC.

* RopLegit

    Since `jmp rcx` gadget is subject to CFG bitmap contrl. This is sort of a work around to use `jmp rdx` gadget and a `CREATE_SUSPENDED` thread to get code execution. But, it's not that 'effective' since you have to take into consideration too many things (register thingy...), the process will crash. Just a work around like I said.

* RopCfgFree

    This is the ultimate go if ever have to use a ROP gadget. A gadget in `bcyrpt.dll` can be used to bypass CFG and get code execution theoretically on any process that has `bcrypt.dll` loaded. Tested on windows 1809, 1909 (chances of failure, reason unknown yet), 21H1, 22H2, windows 11 22H2. Note that once `SetProcessValidCallTargets` is successful, and the process remains alive, CFG on that specifc address is always disabled. Have fun!

# Credit

* [FuzzySecurity/Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/UrbanBishop/UrbanBishop.sln) @b33f
* MalDevAcademy @mrd0x @NUL0x4C
