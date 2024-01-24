#pragma once

#ifndef _HASHING_H
#define _HASHING_H

#include <windows.h>
#include "log.h"

#define _HASHA(API) jenkinsa(API)
#define _HASHW(API) jenkinsw(API)

DWORD jenkinsa(_In_ PCHAR String);
DWORD jenkinsw(_In_ PWCHAR String);

#endif    //!HASHING_H
