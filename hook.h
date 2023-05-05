#include "util.h"
#include "mmap.h"
#include "ntdef.h"


extern BYTE ioinitsystem_old_bytes[23];
extern VOID(*IofCompleteRequest)(PIRP Irp, CHAR8* PriorityBoost);
extern UINT32(*IoInitSystem)();
extern VOID* g_kernel_base;
extern CHAR16 g_module_path[260];

VOID Hook_IoInitSystem(UINT8* _ioInitSystem, VOID* func);
// This doesn't actually point to the top of IoInitSystem, it points to after IoInitSystemPreDrivers, which is number of bytes in.
VOID IoInitSystemHook();