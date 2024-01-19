#pragma once

#ifndef _HASHING_H
#define _HASHING_H

#include <windows.h>

#define _HASH(API) jenkins(API)

DWORD jenkins(_In_ PCHAR String);

#endif    //!HASHING_H
