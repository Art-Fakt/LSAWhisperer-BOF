/*
 * lsa_bofdefs.h - Additional DFR declarations for LSA Whisperer BOF
 *
 * The main _include/bofdefs.h already has most DFR declarations.
 * This file adds the ones specific to LSA communication that are
 * missing from the shared header.
 */
#pragma once

#include "beacon.h"
#include "bofdefs.h"

/* ============================================================
 * Additional SECUR32 DFR - LSA Privileged Connection
 * (Not in the shared bofdefs.h)
 * ============================================================ */

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaRegisterLogonProcess(
    PVOID LogonProcessName,    /* PLSA_STRING */
    PHANDLE LsaHandle,
    PVOID SecurityMode         /* PLSA_OPERATIONAL_MODE */
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaEnumerateLogonSessions(
    PULONG LogonSessionCount,
    PLUID* LogonSessionList
);

/* ============================================================
 * Additional NTDLL DFR
 * ============================================================ */

DECLSPEC_IMPORT ULONG NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS Status);

/* ============================================================
 * Additional MSVCRT DFR
 * ============================================================ */

#ifndef MSVCRT_STRTOUL_DEFINED
#define MSVCRT_STRTOUL_DEFINED
DECLSPEC_IMPORT unsigned long MSVCRT$strtoul(const char*, char**, int);
#endif

#ifndef MSVCRT_STRICMP_DEFINED
#define MSVCRT_STRICMP_DEFINED
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
#endif

/* ============================================================
 * Convenience Macros (matching lsawhisper naming)
 * ============================================================ */

/* Heap allocation - use the Adaptix intAlloc/intFree names too */
#define HEAP_ALLOC(size)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define HEAP_FREE(ptr)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (ptr))

/* String helpers */
#define STRLEN    MSVCRT$strlen
#define STRCMP     MSVCRT$strcmp
#define STRICMP   MSVCRT$_stricmp
#define STRCPY    MSVCRT$strcpy
#define STRCAT    MSVCRT$strcat
#define MEMSET    MSVCRT$memset
#define MEMCPY    MSVCRT$memcpy
#define MEMCMP    MSVCRT$memcmp
#define SPRINTF   MSVCRT$sprintf
#define SNPRINTF  MSVCRT$_snprintf

/* NTSTATUS helpers */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
