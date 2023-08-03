#pragma once

#include <stdio.h>

#include <metahost.h>
#pragma comment(lib, "MSCorEE.lib")

#import "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.tlb" raw_interfaces_only  \
    high_property_prefixes("_get","_put","_putref")		                                    \
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;