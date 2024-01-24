#pragma once

#ifndef _PEBWALKING_H
#define _PEBWALKING_H

#include <windows.h>
#include "structs.h"
#include "hashing.h"
#include "apisets.h"
#include "log.h"

char to_upper(_In_ char);
HMODULE get_mod_hndl_by_hash(_In_ DWORD);
FARPROC get_proc_addr_by_hash(_In_ HMODULE, _In_ DWORD);

#endif // !PEBWALKING_H
