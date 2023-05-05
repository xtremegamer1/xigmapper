#include "mmap.h"


NTSTATUS (*NtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
);

NTSTATUS (*NtQueryInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS (*ZwReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PVOID  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	UINT64*   ByteOffset,
	ULONG*           Key
);

PVOID (*ExAllocatePoolWithTag) (
	POOL_TYPE										PoolType,
	UINT64                                         NumberOfBytes,
	ULONG                                          Tag
	);

NTSTATUS (*ZwClose)(
	HANDLE Handle
);

void (*ExFreePoolWithTag)(
	PVOID P,
	ULONG Tag
);

NTSTATUS ManualMapFile (CHAR16* FileName)
{
	// Open file by name
#pragma warning (push)
#pragma warning (disable : 4152)
	if (!NtOpenFile)
		NtOpenFile = FindExport(g_kernel_base, "NtOpenFile");
	if (!NtQueryInformationFile)
		NtQueryInformationFile = FindExport(g_kernel_base, "NtQueryInformationFile");
	if (!ZwReadFile)
		ZwReadFile = FindExport(g_kernel_base, "ZwReadFile");
	if (!ExAllocatePoolWithTag)
		ExAllocatePoolWithTag = FindExport(g_kernel_base, "ExAllocatePoolWithTag");
	if (!ZwClose)
		ZwClose = FindExport(g_kernel_base, "ZwClose");
	if (!ExFreePoolWithTag)
		ExFreePoolWithTag = FindExport(g_kernel_base, "ExFreePoolWithTag");
#pragma warning (pop)

	UNICODE_STRING str = {(UINT16)StrLen(FileName) * 2, (UINT16)StrLen(FileName) * 2, FileName};
	OBJECT_ATTRIBUTES attrib = {sizeof(OBJECT_ATTRIBUTES), NULL, &str, 0x00000040L, NULL, NULL};
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK status_block;
	NTSTATUS status = NtOpenFile(&FileHandle, GENERIC_READ, &attrib, &status_block, 0, FILE_SYNCHRONOUS_IO_NONALERT);
	if (status < 0)
		return status;
	FILE_STANDARD_INFORMATION info;
	status = NtQueryInformationFile(FileHandle, &status_block, &info, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (status < 0)
		goto endfunc;
	UINT64 size = info.EndOfFile;
	
	BYTE* buf = ExAllocatePoolWithTag(NonPagedPool, size, 'sgin');
	if (!buf)
		goto endfunc;
	UINT64 byte_offset = 0;
	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &status_block, buf, (ULONG)size, &byte_offset, NULL);
	if (status < 0)
		goto freepool;
	status = ManualMapArray(buf, size);

freepool:
	ExFreePoolWithTag(buf, 'sgin');
endfunc:
	ZwClose(FileHandle);
	return status;
}

PMDL (*MmAllocatePagesForMdl)(
	PHYSICAL_ADDRESS LowAddress,
	PHYSICAL_ADDRESS HighAddress,
	PHYSICAL_ADDRESS SkipBytes,
	UINT64           TotalBytes
);

PVOID (*MmMapLockedPages)(
	PMDL			MemoryDescriptorList,
	KPROCESSOR_MODE AccessMode
);

ULONG (*DbgPrint)(
	const CHAR8* Format,
	...
);

NTSTATUS ManualMapArray(BYTE* bytes, UINT64 size)
{
#pragma warning (push)
#pragma warning (disable : 4152)
	if (!MmAllocatePagesForMdl)
		MmAllocatePagesForMdl = FindExport(g_kernel_base, "MmAllocatePagesForMdl");
	if (!MmMapLockedPages)
		MmMapLockedPages = FindExport(g_kernel_base, "MmMapLockedPages");
	if (!DbgPrint)
		DbgPrint = FindExport(g_kernel_base, "DbgPrint");
#pragma warning (pop)

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)bytes;
	if (dos->e_magic != 'ZM')
		return STATUS_INVALID_PARAMETER;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(bytes + dos->e_lfanew);
	if (nt->Signature != (UINT32)'EP')
		return STATUS_INVALID_PARAMETER;

	// Allocate mdl
	PMDL mdl = MmAllocatePagesForMdl(0, ~0ull, 0, nt->OptionalHeader.SizeOfImage);
	BYTE* AllocationBase = MmMapLockedPages(mdl, KernelMode);

	// Copy sections one at a time (no need to copy the headers)
	PIMAGE_SECTION_HEADER sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
		Copy_Memory(AllocationBase + sec_hdr->VirtualAddress, bytes + sec_hdr->PointerToRawData, sec_hdr->SizeOfRawData);

	// Imports
	PIMAGE_DATA_DIRECTORY import_dir = &nt->OptionalHeader.DataDirectory[1];
	for (PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)(AllocationBase + import_dir->VirtualAddress); desc->LookupTableRVA; ++desc)
	{
		// Get unicode name from ascii name
		CHAR16 buffer[260];
		CHAR8* mod_name = (CHAR8*)(AllocationBase + desc->Name);
		for (int i = 0; i < 259 && mod_name[i]; ++i)
			buffer[i] = (CHAR16)mod_name[i], buffer[i + 1] = L'\0';
		PVOID module_base = GetLoadedModuleBase(buffer);
		for (UINT64* lookup_entry = (UINT64*)(AllocationBase + desc->LookupTableRVA), *iat_entry = (UINT64*)(AllocationBase + desc->ImportAddressTable); *lookup_entry; ++lookup_entry, ++iat_entry)
		{
			if (*lookup_entry & (1ull << 63))
				*(PVOID*)iat_entry = FindExportByOrdinal(module_base, *lookup_entry & 0xFFFF);
			else
				*(PVOID*)iat_entry = FindExport(module_base, ((RELOC_NAME_TABLE_ENTRY*)(AllocationBase + (*lookup_entry & 0x7FFFFFFF)))->Name);
		}
	}

	// Relocations
	INT64 load_delta = (INT64)(AllocationBase - nt->OptionalHeader.ImageBase);
	PIMAGE_DATA_DIRECTORY reloc = &nt->OptionalHeader.DataDirectory[5];
	for (PRELOC_BLOCK_HDR i = (PRELOC_BLOCK_HDR)(AllocationBase + reloc->VirtualAddress); i < (PRELOC_BLOCK_HDR)(AllocationBase + reloc->VirtualAddress + reloc->Size); *(BYTE**)&i += i->BlockSize)
		for (PRELOC_ENTRY entry = (PRELOC_ENTRY)i + 4; (BYTE*)entry < (BYTE*)i + i->BlockSize; ++entry)
			if (entry->Type == 0xA)
				*(UINT64*)(AllocationBase + i->PageRVA + entry->Offset) += load_delta;
	
	// Unload discardable sections
	sec_hdr = (PIMAGE_SECTION_HEADER)((BYTE*)(&nt->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec_hdr++)
		if (sec_hdr->Characteristics & 0x02000000)
			Set_Memory(AllocationBase + sec_hdr->VirtualAddress, sec_hdr->SizeOfRawData, 0x00);

	// Call DriverEntry
	NTSTATUS(*DriverEntry)(DEVICE_OBJECT * DeviceObject, PUNICODE_STRING RegistryPath) = 
		(NTSTATUS(*)(DEVICE_OBJECT *, PUNICODE_STRING))(AllocationBase + nt->OptionalHeader.AddressOfEntryPoint);

	return DriverEntry((DEVICE_OBJECT*)0, (PUNICODE_STRING)0);
}