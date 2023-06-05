/*
* 
* Native application for testing persistence in BootExecute registry key
*
*/

#include <Windows.h>
#include <winternl.h>

// entry point
extern void __stdcall NtProcessStartup(void* Argument)
{
	UNICODE_STRING filePath;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;

	RtlInitUnicodeString(&filePath, L"\\??\\\\C:\\Users\\oprop\\Downloads\\temp\\woohoo.txt");

	InitializeObjectAttributes(&objectAttributes, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NtCreateFile(&fileHandle, GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);

	return;
}

