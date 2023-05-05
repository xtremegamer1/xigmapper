#pragma once
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include "ntdef.h"

#define CASE_INSENSITIVE
#define CASE_SENSITIVE


CHAR16* const FormatGuid(CHAR16* const output, GUID guid);

UINT64 PatternScan(const CHAR8* pattern, VOID* address, UINT64 size, BOOLEAN backwards);

KLDR_DATA_TABLE_ENTRY* GetModuleFromList(LIST_ENTRY* head, const CASE_INSENSITIVE CHAR16* mod_name);
VOID* GetLoadedModuleBase(const CASE_INSENSITIVE CHAR16* mod_name);

UINT32* FindExportEntry(VOID* module, const CASE_SENSITIVE CHAR8* routine_name);
VOID* FindExport(VOID* module, const CASE_SENSITIVE CHAR8* routine_name);

UINT32* FindExportEntryByOrdinal(VOID* module, UINT16 ordinal);
VOID* FindExportByOrdinal(VOID* module, UINT16 ordinal);

VOID** FindImportEntry(VOID* module, const CASE_INSENSITIVE CHAR8* routine_module, const CASE_SENSITIVE CHAR8* routine_name);
VOID* FindImport(VOID* module, const CASE_INSENSITIVE CHAR8* routine_module, const CASE_SENSITIVE CHAR8* routine_name);

INTN u_wcsnicmp(const CHAR16* First, const CHAR16* Second, UINTN Length);
_declspec(noinline) INTN ascii_strcmp(const CHAR8* first, const CHAR8* second); // This is to make it easier to debug, because the AsciiStrCmp creates shit assembly
void Copy_Memory(const VOID* Dest, const VOID* Src, UINTN Len);
void Readonly_Copy_Memory(const VOID* Dest, const VOID* Src, UINTN Len);
void Set_Memory(VOID* Dest, UINTN Len, CHAR8 Val);