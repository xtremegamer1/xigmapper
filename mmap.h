#include "ntdef.h"
#include "util.h"

extern VOID* g_kernel_base;

NTSTATUS ManualMapFile(CHAR16* FileName);
NTSTATUS ManualMapArray(BYTE* bytes, UINT64 size);