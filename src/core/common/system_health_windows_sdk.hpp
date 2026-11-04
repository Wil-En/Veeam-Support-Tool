#pragma once

// Shared Windows SDK include contract for the System Health collector.
//
// Microsoft requires Winsock2 to be included before Windows/IP Helper headers
// when IP Helper uses Winsock 2 data types. Netioapi.h additionally requires
// ws2def.h and ws2ipdef.h before Iphlpapi.h includes it. Winsock2 supplies
// ws2def.h; ws2ipdef.h is included explicitly. Netioapi.h must not be included
// directly.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <tlhelp32.h>

#ifndef _WS2DEF_
#error "System Health Windows SDK contract requires ws2def.h via winsock2.h."
#endif

#ifndef _WS2IPDEF_
#error "System Health Windows SDK contract requires ws2ipdef.h before iphlpapi.h."
#endif
