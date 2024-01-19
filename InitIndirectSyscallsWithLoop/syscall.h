#pragma once

#ifndef _SYSCALL_H
#define _SYSCALL_H

#include <windows.h>
#include "apisets.h"
#include "hashing.h"
#include "structs.h"

#define _UP -32
#define _DOWN 32
#define _RANGE 0xFF

BOOL resolve_nt_syscall(_In_ DWORD, _Out_ PNT_SYSCALL);

#endif // !SYSCALL_H

