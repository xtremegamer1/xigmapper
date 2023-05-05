#include "util.h"
#include "ntdef.h"

UINT64 ascii_to_int(CHAR8* ascii)
{
    UINT64 return_int = 0;
    while (*ascii)
    {
        if (*ascii <= '0' || *ascii >= '9')
            return 0;
        return_int *= 10;
        return_int += *ascii - '0';
        ascii++;
    }
    return return_int;
}


UINT32* FindExportEntry(VOID* module, const CASE_SENSITIVE CHAR8* routine_name)
{
    PIMAGE_DOS_HEADER dos = module;
    if (dos->e_magic != 0x5A4D)
        return NULL;
    
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)module + dos->e_lfanew);
    UINT32 exports_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress; // This corresponds to export directory
    if (!exports_rva)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)module + exports_rva);
    UINT32* name_table = (UINT32*)((UINT8*)module + export_dir->AddressOfNames);

    // Binary Search
    for (int lower = 0, upper = export_dir->NumberOfNames - 1; upper >= lower;)
    {
        int i = (upper + lower) / 2;
        const CHAR8* func_name = (CHAR8*)((UINT8*)module + name_table[i]);
        INTN diff = ascii_strcmp(routine_name, func_name);
        if (diff > 0)
            lower = i + 1;
        else if (diff < 0)
            upper = i - 1;
        else
        {
            UINT32* export_func_table = (UINT32*)((UINT8*)module + export_dir->AddressOfFunctions);
            UINT16* ordinal_table = (UINT16*)((UINT8*)module + export_dir->AddressOfNameOrdinals);

            UINT16 index = ordinal_table[i];
            if (export_func_table[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress ||
                export_func_table[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
                return export_func_table + index;
            // Handle the case of a forwarder export entry
            else
            {
                CHAR16 buffer[260];
                CHAR8* forwarder_rva_string = (CHAR8*)module + export_func_table[index];
                UINT16 dll_name_length;
                for (dll_name_length = 0; dll_name_length < 259; ++dll_name_length)
                    if (forwarder_rva_string[dll_name_length] == '.') break;
                for (int j = 0; j < dll_name_length; ++j)
                    buffer[j] = (CHAR16)forwarder_rva_string[j];
                buffer[dll_name_length] = L'\0';
                if (forwarder_rva_string[dll_name_length + 1] == '#')
                    return FindExportEntryByOrdinal(GetLoadedModuleBase(buffer), (UINT16)ascii_to_int(&forwarder_rva_string[dll_name_length + 2]));
                else
                    return FindExportEntry(GetLoadedModuleBase(buffer), &forwarder_rva_string[dll_name_length + 2]);
            }
        }
    }
    return NULL;
}

UINT32* FindExportEntryByOrdinal(VOID* module, UINT16 ordinal)
{
    PIMAGE_DOS_HEADER dos = module;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)module + dos->e_lfanew);
    UINT32 exports_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress; // This corresponds to export directory
    if (!exports_rva)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)module + exports_rva);
    UINT16 index = ordinal - (UINT16)export_dir->Base;

    UINT32* export_func_table = (UINT32*)((UINT8*)module + export_dir->AddressOfFunctions);
    if (export_func_table[index] < nt->OptionalHeader.DataDirectory[0].VirtualAddress || 
        export_func_table[index] > nt->OptionalHeader.DataDirectory[0].VirtualAddress + nt->OptionalHeader.DataDirectory[0].Size)
        return export_func_table + index;
    // Handle the case of a forwarder export entry
    else
    {
        CHAR16 buffer[260];
        CHAR8* forwarder_rva_string = (CHAR8*)module + export_func_table[index];
        UINT16 dll_name_length;
        for (dll_name_length = 0; dll_name_length < 259; ++dll_name_length)
            if (forwarder_rva_string[dll_name_length] == '.') break;
        for (int i = 0; i < dll_name_length; ++i)
            buffer[i] = (CHAR16)forwarder_rva_string[i];
        buffer[dll_name_length] = L'\0';
        if (forwarder_rva_string[dll_name_length + 1] == '#')
            return FindExportEntryByOrdinal(GetLoadedModuleBase(buffer), (UINT16)ascii_to_int(&forwarder_rva_string[dll_name_length + 2]));
        else
            return FindExportEntry(GetLoadedModuleBase(buffer), &forwarder_rva_string[dll_name_length + 2]);
    }
}

VOID* FindExport(VOID* module, const CASE_SENSITIVE CHAR8* routine_name)
{
    UINT32* entry = FindExportEntry(module, routine_name);
    if (!entry)
        return NULL;
    return (VOID*)((UINT8*)module + *entry);
}

VOID* FindExportByOrdinal(VOID* module, UINT16 ordinal)
{
    UINT32* entry = FindExportEntryByOrdinal(module, ordinal);
    if (!entry)
        return NULL;
    return (VOID*)((UINT8*)module + *entry);
}

// This returns a pointer within the IAT, not the entry itself
VOID** FindImportEntry(VOID* module, const CASE_INSENSITIVE CHAR8* routine_module, const CASE_SENSITIVE CHAR8* routine_name)
{
    PIMAGE_DOS_HEADER dos = module;
    if (dos->e_magic != 0x5A4D)
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS)((UINT8*)module + dos->e_lfanew);
    UINT32 imports_rva = nt->OptionalHeader.DataDirectory[1].VirtualAddress; // This corresponds to import directory
    if (!imports_rva)
        return NULL;

    PIMAGE_IMPORT_DESCRIPTOR import_dir = (PIMAGE_IMPORT_DESCRIPTOR)((UINT8*)module + imports_rva);
    // Find the appropriate import directory table entry
    for (int i = 0;; i++)
    {
        if (!import_dir[i].Name)
            return NULL;
        const CHAR8* mod_name = (const CHAR8*)module + import_dir[i].Name;
        if (!AsciiStriCmp(mod_name, routine_module))
        {
            import_dir += i;
            break;
        }
    }

    UINT64* lookup_table = (UINT64*)((UINT8*)module + import_dir->LookupTableRVA);
    for (int i = 0; lookup_table[i]; ++i)
    {
        if (lookup_table[i] & (1ull << 63))
            break; // Import by ordinal
        PIMAGE_IMPORT_BY_NAME entry = (PIMAGE_IMPORT_BY_NAME)((UINT8*)module + lookup_table[i]);
        if (!ascii_strcmp(entry->Name, routine_name))
        {
            VOID** ImportAddressTable = (VOID**)((UINT8*)module + import_dir->ImportAddressTable);
            return ImportAddressTable + i;
        }
    }
    return NULL;
}

VOID* FindImport(VOID* module, const CASE_INSENSITIVE CHAR8* routine_module, const CASE_SENSITIVE CHAR8* routine_name)
{
    VOID** entry = FindImportEntry(module, routine_module, routine_name);
    if (!entry)
        return NULL;
    return *entry;
}

CHAR16 wc_to_lower(CHAR16 c)
{
    if (c >= 'A' && c <= 'Z')
        return c += ('a' - 'A');
    else return c;
}

INTN u_wcsnicmp(const CHAR16* First, const CHAR16* Second, UINTN Length)
{
    for (int i = 0; i < Length && First[i] && Second[i]; ++i) // Channeling my inner Python developer
        if (wc_to_lower(First[i]) != wc_to_lower(Second[i]))
            return First[i] - Second[i];

    return 0;
}

KLDR_DATA_TABLE_ENTRY* GetModuleFromList(LIST_ENTRY* head, const CASE_INSENSITIVE CHAR16* mod_name)
{
    for (LIST_ENTRY* it = head->ForwardLink; it && it != head; it = it->ForwardLink)
    {
        KLDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(it, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!u_wcsnicmp(entry->BaseDllName.Buffer, mod_name, entry->BaseDllName.Length))
        {
            return entry;
        }
    }
    return NULL;
}

extern VOID* g_kernel_base;
VOID* GetLoadedModuleBase(const CASE_INSENSITIVE CHAR16* mod_name)
{
    static LIST_ENTRY* PsLoadedModuleList;
    if (!PsLoadedModuleList)
        PsLoadedModuleList = FindExport(g_kernel_base, "PsLoadedModuleList");
    
    KLDR_DATA_TABLE_ENTRY* module = GetModuleFromList(PsLoadedModuleList, mod_name);
    if (!module)
        return NULL;
    return module->DllBase;
}

// This formats a guid in microsoft mixed endian. The out buffer must be 39 bytes
CHAR16* const FormatGuid(CHAR16* const output, GUID guid)
{
    CHAR16* formatted = CatSPrint(NULL, L"{%8X-%4X-%4X-%4X-%2X%2X%2X%2X%2X%2X}",
        guid.Data1, guid.Data2, guid.Data3, *(UINT16*)guid.Data4,
        guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    StrCpyS(output, 39, formatted);
    FreePool(formatted);
    return output;
}

static BOOLEAN isDigit(CHAR8 character)
{
    return (character >= '0' && character <= '9') || (character >= 'A' && character <= 'F') || (character >= 'a' && character <= 'f');
}

static UINT8 ByteFromString(const CHAR8* str)
{
    UINT8 byte = 0;
    CHAR8 hi_digit = str[0];
    if (hi_digit >= '0' && hi_digit <= '9')
        byte |= ((hi_digit - '0') << 4);
    else if (hi_digit >= 'A' && hi_digit <= 'F')
        byte |= ((hi_digit - 'A' + 10) << 4);
    else if (hi_digit >= 'a' && hi_digit <= 'f')
        byte |= ((hi_digit - 'a' + 10) << 4);
    else return 0; // unreachable

    CHAR8 lo_digit = str[1];
    if (lo_digit >= '0' && lo_digit <= '9')
        byte |= (lo_digit - '0');
    else if (lo_digit >= 'A' && lo_digit <= 'F')
        byte |= (lo_digit - 'A' + 10);
    else if (lo_digit >= 'a' && lo_digit <= 'f')
        byte |= (lo_digit - 'a' + 10);
    else return 0; // unreachable

    return byte;
}

_declspec(noinline) INTN ascii_strcmp(const CHAR8* first, const CHAR8* second)
{
    return AsciiStrCmp(first, second);
}

// Pattern strings are ascii strings containing 2-character tokens separated by spaces. These tokens can either be 2 hex digits or 2 question marks. A pattern string musn't end in a space.
// Example: "ef cd ab 89 67 45 23 01 ?? ?? DE AD BE EF" is a valid pattern string
// Some invalid strings: "", "?a", "123456deadbeef", "3a ? 3b", "01, 23, 45", "0x01 0x02 0x03", "01 02 03 ?? "
static UINT64 ValidatePatternString(const CHAR8* const pattern_string)
{
    for (int i = 0; pattern_string[i]; i += 3)
    {
        // Validate that there are no null characters in the first 2
        if (!(pattern_string[i] && pattern_string[i + 1])) // Short-circuit evaluation prevents reads past the null terminator :)
            return 0;
        // Third can be either a null terminator or a space
        if (pattern_string[i + 2] != ' ' && pattern_string[i + 2] != '\0')
            return 0;
        // First 2 can either both be question marks, or both be hex digits
        if (!(isDigit(pattern_string[i]) || pattern_string[i] == '?') || !(isDigit(pattern_string[i + 1]) || pattern_string[i + 1] == '?'))
            return 0;
        if (isDigit(pattern_string[i]) != isDigit(pattern_string[i + 1]))
            return 0;

        // We have a valid 3-byte block. If it contains a null terminator, we return, otherwise continue
        if (pattern_string[i + 2] == '\0')
            return (i / 3) + 1;
    }
    // This means an otherwise valid string ended in a space. We will consider this invalid.
    return 0;
}

// A range musn't cross 0 or 7fffffffffff, and it musn't touch non-canonical territory.
static BOOLEAN ValidateRange(VOID* start, UINT64 size, BOOLEAN backwards)
{
    if (size > 0x7fffffffffff)
        return FALSE;

    UINT64 sign_extend = (UINT64)start >> 47;
    if (sign_extend != 0x1ffff && sign_extend != 0x00000)
        return FALSE;

    VOID* end = (VOID*)(backwards ? (UINT8*)start - size : (UINT8*)start + size);
    sign_extend = (UINT64)end >> 47;
    if (sign_extend != 0x1ffff && sign_extend != 0x00000)
        return FALSE;

    if (backwards)
    {
        if (end > start)
            return FALSE;
    }
    else
    {
        if (end < start)
            return FALSE;
    }

    return TRUE;
}

UINT64 PatternScan(const CHAR8* pattern, VOID* address, UINT64 size, BOOLEAN backwards)
{
    if (!ValidateRange(address, size, backwards)) return 0;
    UINT64 length = ValidatePatternString(pattern);
    if (!length)
        return 0;

    // It is forbidden for the end of the pattern to hang over the end of the range (or the beginning if the pattern is backwards)
    size -= (length - 1);
    if (backwards)
        address = (VOID*)((UINT8*)address - (length - 1));

    for (UINT8* i = (UINT8*)address; backwards ? i > (UINT8*)address - size : i < (UINT8*)address + size; backwards ? --i : ++i)
    {
        for (int j = 0; j < length; ++j)
        {
            if (pattern[3 * j] != '?')
            {
                UINT8 byte = ByteFromString(pattern + (3 * j));
                if (byte != i[j])
                    break;
            }
            if (j == length - 1)
                return (UINT64)i;
        }
    }

    return 0;
}

void Copy_Memory(const VOID* Dest, const VOID* Src, UINTN Len) // CopyMem relies on boot services
{
    for (int i = 0; i < Len; ++i)
    {
        ((UINT8*)Dest)[i] = ((UINT8*)Src)[i];
    }
}

void Readonly_Copy_Memory(const VOID* Dest, const VOID* Src, UINTN Len)
{
    // This horrendous spagetti code allows interrupt safety and to write readonly regardless of the status of control registers
    UINT64 interrupts_enabled = __readeflags() & 0x200;
    if (interrupts_enabled)
        _disable();
    UINT64 cr4 = __readcr4();
    __writecr4(cr4 & ~0x800000ull); // Disable CET
    UINT64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ull); // Disable WP

    Copy_Memory(Dest, Src, Len);

    __writecr0(cr0);
    __writecr4(cr4);
    if (interrupts_enabled)
        _enable();
}

void Set_Memory(VOID* Dest, UINTN Len, CHAR8 Val)
{
    for (int i = 0; i < Len; ++i)
    {
        ((volatile UINT8*)Dest)[i] = Val;
    }
}
