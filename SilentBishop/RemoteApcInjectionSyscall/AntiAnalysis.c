#include "Structs.h"
#include "AntiAnalysis.h"

BOOL TimeTickCheck()
{
	DWORD	dwTime1 = NULL,
		dwTime2 = NULL;

	dwTime1 = GetTickCount64();

	Sleep(1000);

	dwTime2 = GetTickCount64();

	if ((dwTime2 - dwTime1) < 500) return TRUE;

	return FALSE;
}
