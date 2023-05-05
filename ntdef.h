#pragma once
#pragma warning( push )
#pragma warning (disable : 4201 4324)

#include <ntstatus.h>

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (UINT64)(&((type *)0)->field)))

typedef struct _UNICODE_STRING
{
    UINT16 Length;
    UINT16 MaximumLength;
    CHAR16* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef short CSHORT;
typedef unsigned short USHORT;
typedef long LONG;
typedef unsigned long ULONG;
typedef VOID* PVOID;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef CHAR8 CCHAR;
typedef CCHAR KPROCESSOR_MODE;
typedef ULONG DEVICE_TYPE, ACCESS_MASK;
typedef long NTSTATUS;
typedef PVOID PIO_TIMER, PVPB, PSECURITY_DESCRIPTOR, PDRIVER_EXTENSION, PFAST_IO_DISPATCH, PDRIVER_INITIALIZE, PDRIVER_STARTIO, PDRIVER_UNLOAD, PDRIVER_DISPATCH;
typedef unsigned char BYTE;
typedef struct _OBJECT_TYPE OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

    //
    //  These are special versions of these operations (defined earlier)
    //  which can be used by kernel mode drivers only to bypass security
    //  access checks for Rename and HardLink operations.  These operations
    //  are only recognized by the IOManager, a file system should never
    //  receive these.
    //

    FileRenameInformationBypassAccessCheck,         // 56
    FileLinkInformationBypassAccessCheck,           // 57

    //
    // End of special information classes reserved for IOManager.
    //

    FileVolumeNameInformation,                      // 58
    FileIdInformation,                              // 59
    FileIdExtdDirectoryInformation,                 // 60
    FileReplaceCompletionInformation,               // 61
    FileHardLinkFullIdInformation,                  // 62
    FileIdExtdBothDirectoryInformation,             // 63
    FileDispositionInformationEx,                   // 64
    FileRenameInformationEx,                        // 65
    FileRenameInformationExBypassAccessCheck,       // 66
    FileDesiredStorageClassInformation,             // 67
    FileStatInformation,                            // 68
    FileMemoryPartitionInformation,                 // 69
    FileStatLxInformation,                          // 70
    FileCaseSensitiveInformation,                   // 71
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75
    FileKnownFolderInformation,   // 76

    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_STANDARD_INFORMATION {
    UINT64 AllocationSize;
    UINT64 EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef struct _RELOC_BLOCK_HDR
{
    UINT32 PageRVA;
    UINT32 BlockSize;
} RELOC_BLOCK_HDR, *PRELOC_BLOCK_HDR;

typedef struct _RELOC_ENTRY
{
    UINT16 Offset : 12;
    UINT16 Type : 4;
} RELOC_ENTRY, * PRELOC_ENTRY;

typedef struct _RELOC_NAME_TABLE_ENTRY
{
    UINT16 Hint;
    CHAR8 Name[];
} RELOC_NAME_TABLE_ENTRY, PRELOC_NAME_TABLE_ENTRY;

//
//  The following are masks for the predefined standard access types
//

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

//
// AccessSystemAcl access type
//

#define ACCESS_SYSTEM_SECURITY           (0x01000000L)

//
// MaximumAllowed access type
//

#define MAXIMUM_ALLOWED                  (0x02000000L)

//
//  These are the generic rights.
//

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L


//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#define FILE_DISALLOW_EXCLUSIVE                 0x00020000

#define FILE_SESSION_AWARE                      0x00040000

//
//  CreateOptions flag to pass in call to CreateFile to allow the write through xro.sys
//

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe


typedef  NTSTATUS (*p_ObReferenceObjectByName)(PUNICODE_STRING ObjectName,

    ULONG Attributes,

    PVOID AccessState,

    ACCESS_MASK DesiredAccess,

    POBJECT_TYPE ObjectType,

    KPROCESSOR_MODE AccessMode,

    PVOID ParseContext OPTIONAL,

    PVOID* Object);

#define IRP_MJ_MAXIMUM_FUNCTION 0x1b

extern p_ObReferenceObjectByName ObReferenceObjectByName;

typedef struct _MDL {
    struct _MDL* Next;
    CSHORT Size;
    CSHORT MdlFlags;

    struct _EPROCESS* Process;
    PVOID MappedSystemVa;   /* see creators for field size annotations. */
    PVOID StartVa;   /* see creators for validity; could be address 0.  */
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, * PMDL;

typedef struct __declspec(align(16)) _DEVICE_OBJECT {
    CSHORT                   Type;
    USHORT                   Size;
    LONG                     ReferenceCount;
    struct _DRIVER_OBJECT* DriverObject;
    struct _DEVICE_OBJECT* NextDevice;
    struct _DEVICE_OBJECT* AttachedDevice;
    struct _IRP* CurrentIrp;
    PIO_TIMER                Timer;
    ULONG                    Flags;
    ULONG                    Characteristics;
    volatile PVPB            Vpb;
    PVOID                    DeviceExtension;
    DEVICE_TYPE              DeviceType;
    CCHAR                    StackSize;
    union {
        LIST_ENTRY         ListEntry;
        BYTE               Wcb[0x48];
    } Queue;
    ULONG                    AlignmentRequirement;
    ULONG                    pad0;
    BYTE                     DeviceQueue[0x28];
    BYTE                     Dpc[0x40];
    ULONG                    ActiveThreadCount;
    ULONG                    pad1;
    PSECURITY_DESCRIPTOR     SecurityDescriptor;
    BYTE                     DeviceLock[0x18];
    USHORT                   SectorSize;
    USHORT                   Spare1;
    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
    PVOID                    Reserved;
} DEVICE_OBJECT, * PDEVICE_OBJECT;

typedef struct _DEVOBJ_EXTENSION {

    CSHORT          Type;
    USHORT          Size;

    PDEVICE_OBJECT  DeviceObject;               // owning device object

    //
    // The remaining fields are reserved for system use.
    //

    ULONG           PowerFlags;
    struct          _DEVICE_OBJECT_POWER_EXTENSION* Dope;
    ULONG ExtensionFlags;
    PVOID           DeviceNode;
    PDEVICE_OBJECT  AttachedTo;
    volatile LONG StartIoCount;
    LONG           StartIoKey;
    ULONG          StartIoFlags;
    PVPB           Vpb;
    PVOID DependencyNode;
    PVOID InterruptContext;
    volatile LONG InterruptCount;

    volatile PVOID VerifierContext;

} DEVOBJ_EXTENSION, * PDEVOBJ_EXTENSION;

typedef struct _DRIVER_OBJECT {
    CSHORT             Type;
    CSHORT             Size;
    PDEVICE_OBJECT     DeviceObject;
    ULONG              Flags;
    PVOID              DriverStart;
    ULONG              DriverSize;
    PVOID              DriverSection;
    PDRIVER_EXTENSION  DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PFAST_IO_DISPATCH  FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO    DriverStartIo;
    PDRIVER_UNLOAD     DriverUnload;
    PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, * PDRIVER_OBJECT;

typedef struct _LOADER_PARAMETER_BLOCK
{
    UINT32 OsMajorVersion;
    UINT32 OsMinorVersion;
    UINT32 Size;
    UINT32 OsLoaderSecurityVersion;
    struct _LIST_ENTRY LoadOrderListHead;
    struct _LIST_ENTRY MemoryDescriptorListHead;
    struct _LIST_ENTRY BootDriverListHead;
    struct _LIST_ENTRY EarlyLaunchListHead;
    struct _LIST_ENTRY CoreDriverListHead;
    struct _LIST_ENTRY CoreExtensionsDriverListHead;
    struct _LIST_ENTRY TpmCoreDriverListHead;
} LOADER_PARAMETER_BLOCK, * PLOADER_PARAMETER_BLOCK;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;
    VOID* ExceptionTable;
    UINT32 ExceptionTableSize;
    VOID* GpValue;
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
    VOID* DllBase;
    VOID* EntryPoint;
    UINT32 SizeOfImage;
    struct _UNICODE_STRING FullDllName;
    struct _UNICODE_STRING BaseDllName;
    UINT32 Flags;
    UINT16 LoadCount;
    union
    {
        UINT16 SignatureLevel : 4;
        UINT16 SignatureType : 3;
        UINT16 Unused : 9;
        UINT16 EntireField;
    } u1;
    VOID* SectionPointer;
    UINT32 CheckSum;
    UINT32 CoverageSectionSize;
    VOID* CoverageSection;
    VOID* LoadedImports;
    VOID* Spare;
    UINT32 SizeOfImageNotRounded;
    UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_FILE_HEADER
{
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    UINT32 VirtualAddress;
    UINT32 Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    UINT16 Magic;
    UINT8 MajorLinkerVersion;
    UINT8 MinorLinkerVersion;
    UINT32 SizeOfCode;
    UINT32 SizeOfInitializedData;
    UINT32 SizeOfUninitializedData;
    UINT32 AddressOfEntryPoint;
    UINT32 BaseOfCode;
    UINT64 ImageBase;
    UINT32 SectionAlignment;
    UINT32 FileAlignment;
    UINT16 MajorOperatingSystemVersion;
    UINT16 MinorOperatingSystemVersion;
    UINT16 MajorImageVersion;
    UINT16 MinorImageVersion;
    UINT16 MajorSubsystemVersion;
    UINT16 MinorSubsystemVersion;
    UINT32 Win32VersionValue;
    UINT32 SizeOfImage;
    UINT32 SizeOfHeaders;
    UINT32 CheckSum;
    UINT16 Subsystem;
    UINT16 DllCharacteristics;
    UINT64 SizeOfStackReserve;
    UINT64 SizeOfStackCommit;
    UINT64 SizeOfHeapReserve;
    UINT64 SizeOfHeapCommit;
    UINT32 LoaderFlags;
    UINT32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64, IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

typedef struct _IMAGE_DOS_HEADER
{
    UINT16 e_magic;                     // Magic number
    UINT16 e_cblp;                      // Bytes on last page of file
    UINT16 e_cp;                        // Pages in file
    UINT16 e_crlc;                      // Relocations
    UINT16 e_cparhdr;                   // Size of header in paragraphs
    UINT16 e_minalloc;                  // Minimum extra paragraphs needed
    UINT16 e_maxalloc;                  // Maximum extra paragraphs needed
    UINT16 e_ss;                        // Initial (relative) SS value
    UINT16 e_sp;                        // Initial SP value
    UINT16 e_csum;                      // Checksum
    UINT16 e_ip;                        // Initial IP value
    UINT16 e_cs;                        // Initial (relative) CS value
    UINT16 e_lfarlc;                    // File address of relocation table
    UINT16 e_ovno;                      // Overlay number
    UINT16 e_res[4];                    // Reserved words
    UINT16 e_oemid;                     // OEM identifier (for e_oeminfo)
    UINT16 e_oeminfo;                   // OEM information; e_oemid specific
    UINT16 e_res2[10];                  // Reserved words
    INT32 e_lfanew;                     // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER
{
    UINT8 Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
        UINT32 PhysicalAddress;
        UINT32 VirtualSize;
    } Misc;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    UINT32 Characteristics;
    UINT32 TimeDateStamp;
    UINT16 MajorVersion;
    UINT16 MinorVersion;
    UINT32 Name;
    UINT32 Base;
    UINT32 NumberOfFunctions;
    UINT32 NumberOfNames;
    UINT32 AddressOfFunctions;
    UINT32 AddressOfNames;
    UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    UINT32   LookupTableRVA;             // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    UINT32   TimeDateStamp;                  // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    UINT32   ForwarderChain;                 // -1 if no forwarders
    UINT32   Name;
    UINT32   ImportAddressTable;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef IMAGE_IMPORT_DESCRIPTOR * PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    UINT16    Hint;
    CHAR8   Name[];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IO_STATUS_BLOCK {
    union {
        UINT32 Status;
        VOID* Pointer;
    };

    UINT64 Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    UINT32 SortKey;
    BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, * PKDEVICE_QUEUE_ENTRY, * PRKDEVICE_QUEUE_ENTRY;

typedef struct _KAPC {
    UINT8 Type;
    UINT8 AllFlags;
    UINT8 Size;
    UINT8 SpareByte1;
    UINT32 SpareLong0;
    struct _KTHREAD* Thread;
    LIST_ENTRY ApcListEntry;
    VOID* Reserved[3];
    VOID* NormalContext;
    VOID* SystemArgument1;
    VOID* SystemArgument2;
    CHAR8 ApcStateIndex;
    CHAR8 ApcMode;
    BOOLEAN Inserted;
} KAPC, * PKAPC, * PRKAPC;


// TODO: Clean this up
typedef struct _IO_STACK_LOCATION {
    UINT8 MajorFunction;
    UINT8 MinorFunction;
    UINT8 Flags;
    UINT8 Control;

    //
    // The following user parameters are based on the service that is being
    // invoked.  Drivers and file systems can determine which set to use based
    // on the above major and minor function codes.
    //

    // Stupid me deleted all the declspec aligns and they need to be added back
    union {

        //
        // System service parameters for:  NtCreateFile
        //

        struct {
            VOID* SecurityContext;
            UINT32 Options;
            UINT16  FileAttributes;
            UINT16 ShareAccess;
            UINT32  EaLength;
        } Create;

        //
        // System service parameters for:  NtCreateNamedPipeFile
        //
        // Notice that the fields in the following parameter structure must
        // match those for the create structure other than the last longword.
        // This is so that no distinctions need be made by the I/O system's
        // parse routine other than for the last longword.
        //

        struct {
            VOID* SecurityContext;
            UINT32 Options;
            UINT16  Reserved;
            UINT16 ShareAccess;
            VOID* Parameters;
        } CreatePipe;

        //
        // System service parameters for:  NtCreateMailslotFile
        //
        // Notice that the fields in the following parameter structure must
        // match those for the create structure other than the last longword.
        // This is so that no distinctions need be made by the I/O system's
        // parse routine other than for the last longword.
        //

        struct {
            VOID* SecurityContext;
            UINT32 Options;
            UINT16  Reserved;
            UINT16 ShareAccess;
            VOID* Parameters;
        } CreateMailslot;

        //
        // System service parameters for:  NtReadFile
        //

        struct {
            UINT32 Length;
            UINT32  Key;
#if defined(_WIN64)
            UINT32 Flags;
#endif
            UINT64 ByteOffset;
        } Read;

        //
        // System service parameters for:  NtWriteFile
        //

        struct {
            UINT32 Length;
            UINT32  Key;
#if defined(_WIN64)
            UINT32 Flags;
#endif
            UINT64 ByteOffset;
        } Write;

        //
        // System service parameters for:  NtQueryDirectoryFile
        //

        struct {
            UINT32 Length;
            PUNICODE_STRING FileName;
            UINT32 FileInformationClass;
            UINT32  FileIndex;
        } QueryDirectory;

        //
        // System service parameters for:  NtNotifyChangeDirectoryFile / NtNotifyChangeDirectoryFileEx
        //

        struct {
            UINT32 Length;
            UINT32  CompletionFilter;
        } NotifyDirectory;

        //
        // System service parameters for:  NtNotifyChangeDirectoryFile / NtNotifyChangeDirectoryFileEx
        //
        // For minor code IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX
        // N.B. Keep Length and CompletionFilter aligned with NotifyDirectory.
        //

        struct {
            UINT32 Length;
            UINT32  CompletionFilter;
            UINT32  DirectoryNotifyInformationClass;
        } NotifyDirectoryEx;

        //
        // System service parameters for:  NtQueryInformationFile
        //

        struct {
            UINT32 Length;
            UINT32  FileInformationClass;
        } QueryFile;

        //
        // System service parameters for:  NtSetInformationFile
        //

        struct {
            UINT32 Length;
            UINT32  FileInformationClass;
            VOID* FileObject;
            union {
                struct {
                    BOOLEAN ReplaceIfExists;
                    BOOLEAN AdvanceOnly;
                };
                UINT32 ClusterCount;
                VOID* DeleteHandle;
            };
        } SetFile;



        //
        // System service parameters for:  NtQueryEaFile
        //

        struct {
            UINT32 Length;
            VOID* EaList;
            UINT32 EaListLength;
            UINT32  EaIndex;
        } QueryEa;

        //
        // System service parameters for:  NtSetEaFile
        //

        struct {
            UINT32 Length;
        } SetEa;



        //
        // System service parameters for:  NtQueryVolumeInformationFile
        //

        struct {
            UINT32 Length;
            UINT32  FsInformationClass;
        } QueryVolume;



        //
        // System service parameters for:  NtSetVolumeInformationFile
        //

        struct {
            UINT32 Length;
            UINT32  FsInformationClass;
        } SetVolume;

        //
        // System service parameters for:  NtFsControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            UINT32 OutputBufferLength;
            UINT32  InputBufferLength;
            UINT32  FsControlCode;
            VOID* Type3InputBuffer;
        } FileSystemControl;
        //
        // System service parameters for:  NtLockFile/NtUnlockFile
        //

        struct {
            UINT64* Length;
            UINT32  Key;
            UINT64 ByteOffset;
        } LockControl;

        //
        // System service parameters for:  NtFlushBuffersFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtCancelIoFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtDeviceIoControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            UINT32 OutputBufferLength;
            UINT32 __declspec(align(8)) InputBufferLength;
            UINT32 __declspec(align(8)) IoControlCode;
            VOID* Type3InputBuffer;
        } DeviceIoControl;

        //
        // System service parameters for:  NtQuerySecurityObject
        //

        struct {
            UINT32 SecurityInformation;
            UINT32  Length;
        } QuerySecurity;

        //
        // System service parameters for:  NtSetSecurityObject
        //

        struct {
            UINT32 SecurityInformation;
            VOID* SecurityDescriptor;
        } SetSecurity;

        //
        // Non-system service parameters.
        //
        // Parameters for MountVolume
        //

        struct {
            VOID* Vpb;
            VOID* DeviceObject;
        } MountVolume;

        //
        // Parameters for VerifyVolume
        //

        struct {
            VOID* Vpb;
            VOID* DeviceObject;
        } VerifyVolume;

        //
        // Parameters for Scsi with internal device control.
        //

        struct {
            struct _SCSI_REQUEST_BLOCK* Srb;
        } Scsi;



        //
        // System service parameters for:  NtQueryQuotaInformationFile
        //

        struct {
            UINT32 Length;
            VOID* StartSid;
            VOID* SidList;
            UINT32 SidListLength;
        } QueryQuota;

        //
        // System service parameters for:  NtSetQuotaInformationFile
        //

        struct {
            UINT32 Length;
        } SetQuota;



        //
        // Parameters for IRP_MN_QUERY_DEVICE_RELATIONS
        //

        struct {
            UINT32 Type;
        } QueryDeviceRelations;

        //
        // Parameters for IRP_MN_QUERY_INTERFACE
        //

        struct {
            CONST GUID* InterfaceType;
            UINT16 Size;
            UINT16 Version;
            VOID* Interface;
            VOID* InterfaceSpecificData;
        } QueryInterface;

        //
        // Parameters for IRP_MN_QUERY_CAPABILITIES
        //

        struct {
            VOID* Capabilities;
        } DeviceCapabilities;

        //
        // Parameters for IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        //

        struct {
            VOID* IoResourceRequirementList;
        } FilterResourceRequirements;

        //
        // Parameters for IRP_MN_READ_CONFIG and IRP_MN_WRITE_CONFIG
        //

        struct {
            UINT32 WhichSpace;
            VOID* Buffer;
            UINT32 Offset;
            UINT32  Length;
        } ReadWriteConfig;

        //
        // Parameters for IRP_MN_SET_LOCK
        //

        struct {
            BOOLEAN Lock;
        } SetLock;

        //
        // Parameters for IRP_MN_QUERY_ID
        //

        struct {
            UINT32 IdType;
        } QueryId;

        //
        // Parameters for StartDevice
        //

        struct {
            VOID* AllocatedResources;
            VOID* AllocatedResourcesTranslated;
        } StartDevice;

        //
        // Parameters for Cleanup
        //
        // No extra parameters supplied
        //

        //
        // WMI Irps
        //

        struct {
            UINT32 ProviderId;
            VOID* DataPath;
            UINT32 BufferSize;
            VOID* Buffer;
        } WMI;

        //
        // Others - driver-specific
        //

        struct {
            VOID* Argument1;
            VOID* Argument2;
            VOID* Argument3;
            VOID* Argument4;
        } Others;

    } Parameters;

    //
    // Save a pointer to this device driver's device object for this request
    // so it can be passed to the completion routine if needed.
    //

    VOID* DeviceObject;

    //
    // The following location contains a pointer to the file object for this
    // request.
    //

    VOID* FileObject;

    //
    // The following routine is invoked depending on the flags in the above
    // flags field.
    //

    VOID* CompletionRoutine;

    //
    // The following is used to store the address of the context parameter
    // that should be passed to the CompletionRoutine.
    //

    VOID* Context;

} IO_STACK_LOCATION, * PIO_STACK_LOCATION;

typedef struct _IRP {
    INT16 Type;
    UINT16 Size;


    //
    // Define the common fields used to control the IRP.
    //

    //
    // Define a pointer to the Memory Descriptor List (MDL) for this I/O
    // request.  This field is only used if the I/O is "direct I/O".
    //

    VOID* MdlAddress;

    //
    // Flags word - used to remember various flags.
    //

    UINT32 Flags;

    //
    // The following union is used for one of three purposes:
    //
    //    1. This IRP is an associated IRP.  The field is a pointer to a master
    //       IRP.
    //
    //    2. This is the master IRP.  The field is the count of the number of
    //       IRPs which must complete (associated IRPs) before the master can
    //       complete.
    //
    //    3. This operation is being buffered and the field is the address of
    //       the system space buffer.
    //

    union {
        struct _IRP* MasterIrp;
        INT32 IrpCount;
        VOID* SystemBuffer;
    } AssociatedIrp;

    //
    // Thread list entry - allows queuing the IRP to the thread pending I/O
    // request packet list.
    //

    LIST_ENTRY ThreadListEntry;

    //
    // I/O status - final status of operation.
    //

    IO_STATUS_BLOCK IoStatus;

    //
    // Requester mode - mode of the original requester of this operation.
    //

    CHAR8 RequestorMode;

    //
    // Pending returned - TRUE if pending was initially returned as the
    // status for this packet.
    //

    BOOLEAN PendingReturned;

    //
    // Stack state information.
    //

    CHAR8 StackCount;
    CHAR8 CurrentLocation;

    //
    // Cancel - packet has been canceled.
    //

    BOOLEAN Cancel;

    //
    // Cancel Irql - Irql at which the cancel spinlock was acquired.
    //

    UINT8 CancelIrql;

    //
    // ApcEnvironment - Used to save the APC environment at the time that the
    // packet was initialized.
    //

    CHAR8 ApcEnvironment;

    //
    // Allocation control flags.
    //

    UINT8 AllocationFlags;

    //
    // User parameters.
    //

    union {
        PIO_STATUS_BLOCK UserIosb;

        //
        // Context used when the Irp is managed by IoRing and is used by IoRing.
        // UserIosb is used to cancel an Irp, so sharing space with UserIosb
        // let IoRing cancel an Irp based on its context.
        //

        VOID* IoRingContext;
    };

    VOID* UserEvent;
    union {
        struct {
            union {
                VOID* UserApcRoutine;
                VOID* IssuingProcess;
            };
            union {
                VOID* UserApcContext;

                //
                // IoRing object that rolled this Irp, if any.  The completion
                // is processed through this IoRing object.  UserApcRoutine and
                // UserApcContext is not supported when issuing IOs through an
                // IoRing so we union this with UserApcContext.  We did not use
                // UserApcRoutine because IssuingProcess use the same location
                // and is used when an Irp is queued to FileObject and when the
                // Irp is managed by IoRing it is queued to the FileObject.
                //

                struct _IORING_OBJECT* IoRing;
            };
        } AsynchronousParameters;
        UINT64 AllocationSize;
    } Overlay;

    //
    // CancelRoutine - Used to contain the address of a cancel routine supplied
    // by a device driver when the IRP is in a cancelable state.
    //

    VOID* CancelRoutine;

    //
    // Note that the UserBuffer parameter is outside of the stack so that I/O
    // completion can copy data back into the user's address space without
    // having to know exactly which service was being invoked.  The length
    // of the copy is stored in the second half of the I/O status block. If
    // the UserBuffer field is NULL, then no copy is performed.
    //

    VOID* UserBuffer;

    //
    // Kernel structures
    //
    // The following section contains kernel structures which the IRP needs
    // in order to place various work information in kernel controller system
    // queues.  Because the size and alignment cannot be controlled, they are
    // placed here at the end so they just hang off and do not affect the
    // alignment of other fields in the IRP.
    //

    union {

        struct {

            union {

                //
                // DeviceQueueEntry - The device queue entry field is used to
                // queue the IRP to the device driver device queue.
                //

                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;

                struct {

                    //
                    // The following are available to the driver to use in
                    // whatever manner is desired, while the driver owns the
                    // packet.
                    //

                    VOID* DriverContext[4];

                };

            };

            //
            // Thread - pointer to caller's Thread Control Block.
            //

            VOID* Thread;

            //
            // Auxiliary buffer - pointer to any auxiliary buffer that is
            // required to pass information to a driver that is not contained
            // in a normal buffer.
            //

            CHAR8* AuxiliaryBuffer;

            //
            // The following unnamed structure must be exactly identical
            // to the unnamed structure used in the minipacket header used
            // for completion queue entries.
            //

            struct {

                //
                // List entry - used to queue the packet to completion queue, among
                // others.
                //

                LIST_ENTRY ListEntry;

                union {

                    //
                    // Current stack location - contains a pointer to the current
                    // IO_STACK_LOCATION structure in the IRP stack.  This field
                    // should never be directly accessed by drivers.  They should
                    // use the standard functions.
                    //

                    struct _IO_STACK_LOCATION* CurrentStackLocation;

                    //
                    // Minipacket type.
                    //

                    UINT32 PacketType;
                };
            };

            //
            // Original file object - pointer to the original file object
            // that was used to open the file.  This field is owned by the
            // I/O system and should not be used by any other drivers.
            //

            VOID* OriginalFileObject;

        } Overlay;

        //
        // APC - This APC control block is used for the special kernel APC as
        // well as for the caller's APC, if one was specified in the original
        // argument list.  If so, then the APC is reused for the normal APC for
        // whatever mode the caller was in and the "special" routine that is
        // invoked before the APC gets control simply deallocates the IRP.
        //

        KAPC Apc;

        //
        // CompletionKey - This is the key that is used to distinguish
        // individual I/O operations initiated on a single file VOID*.
        //

        VOID* CompletionKey;

    } Tail;

} IRP;

typedef IRP* PIRP;

typedef struct _IF_LH_PHYSICAL_ADDRESS
{
    UINT16 Length;
    BYTE Address[32];
} IF_LH_PHYSICAL_ADDRESS;

#pragma warning( pop )

