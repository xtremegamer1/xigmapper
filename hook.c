#include "hook.h"
#include <intrin.h>

BYTE ioinitsystem_old_bytes[23];

CHAR16 g_module_path[260] = L"\\GLOBAL??\\C:\\yourdriverhere.sys";

VOID IoInitSystemHook()
{
	ManualMapFile(g_module_path);

	Readonly_Copy_Memory((VOID*)IoInitSystem, ioinitsystem_old_bytes, 23);
	return;
}

extern EFI_RUNTIME_SERVICES* gRT;

// Retpoline kicks in after SetVirtualAddressMap, so we cannot hook anywhere that calls into a dll import. Also we need to do the thunk in order to preserve 16-byte stack alignment
VOID Hook_IoInitSystem(UINT8* _ioInitSystem, VOID* func)
{
	Copy_Memory(&ioinitsystem_old_bytes, _ioInitSystem, 23);
	
	gRT->ConvertPointer(EFI_OPTIONAL_PTR, &func);

	static UINT8 bytecode_template[] = 
		{ 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,	// movabs rax, _ioInitSystem
		0x50,															// push rax						; Leave _ioInitSystem as the return address
		0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,		// movabs rax, func
		0xFF, 0xE0 };													// jmp rax
	Readonly_Copy_Memory(_ioInitSystem, bytecode_template, 23);

	VOID* thunk_address = _ioInitSystem;
	gRT->ConvertPointer(EFI_OPTIONAL_PTR, &thunk_address);
	Readonly_Copy_Memory(_ioInitSystem + 2, &thunk_address, 8);
	Readonly_Copy_Memory(_ioInitSystem + 13, &func, 8);
}