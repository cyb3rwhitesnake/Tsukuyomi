#pragma once
#include <windows.h>

// Inline functions

// The InitializeObjectAttributes macro initializes the opaque OBJECT_ATTRIBUTES structure,
// which specifies the properties of an object handle to routines that open handles.
#define InitializeObjectAttributes(p,n,a,r,s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = r; \
        (p)->Attributes = a; \
        (p)->ObjectName = n; \
        (p)->SecurityDescriptor = s; \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)


// The _CLIENT_ID structure is a data structure used in the Windows operating system
// to uniquely identify a process or thread.
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;			/*Unique process identifier.*/
	HANDLE UniqueThread;			/*Unique thread identifier.*/
} CLIENT_ID, * PCLIENT_ID;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057

// This structure is used to define Unicode strings.
typedef struct _UNICODE_STRING {
	USHORT Length;					/*The length, in bytes, of the string stored in Buffer.*/
	USHORT MaximumLength;			/*The length, in bytes, of Buffer.*/
	PWSTR  Buffer;					/*Pointer to a buffer used to contain a string of wide characters.*/
} UNICODE_STRING, * PUNICODE_STRING;
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string

#define GDI_BATCH_BUFFER_SIZE 310

// Totally undocumented
typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;
// https://processhacker.sourceforge.io/doc/struct___g_d_i___t_e_b___b_a_t_c_h.html

// The purpose of the struct TEB_ACTIVE_FRAME_CONTEXT in the Windows operating system is to hold context information
// for an active frame in a thread's execution environment. It is typically used by the operating system to keep track
// of the state and context of active frames in a thread's stack. This information is used by the operating system
// to manage and execute threads in a consistent and efficient manner.
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;
// https://processhacker.sourceforge.io/doc/struct___t_e_b___a_c_t_i_v_e___f_r_a_m_e___c_o_n_t_e_x_t.html

// The structure TEB_ACTIVE_FRAME in the Windows operating system is used to store information about the active frame of a thread's execution.
// This includes the frame's thread ID, window handle, and a pointer to the next active frame in the thread's stack.
// The purpose of this structure is to maintain information about the active frames in a thread's execution for debugging and other purposes.
typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;
// https://processhacker.sourceforge.io/doc/struct___t_e_b___a_c_t_i_v_e___f_r_a_m_e.html


#define GDI_HANDLE_BUFFER_SIZE 60

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

//typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
//typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

typedef struct _RTL_USER_PROCESS_PARAMETERS* PRTL_USER_PROCESS_PARAMETERS;

// The structure "_PEB_LDR_DATA" in the Windows operating system is a data structure that contains information about the dynamic-link libraries (DLLs)
// that are currently loaded in the process. It is used by the operating system to manage and load the DLLs, which are essential for the execution
// of various programs and applications. The structure contains information such as the base address of the DLL, its size, and other details.
// It is used by the operating system to load and unload the DLLs, as well as to resolve any dependencies between the DLLs.
typedef struct _PEB_LDR_DATA
{
    ULONG Length;									/*This parameter specifies the size, in bytes, of the data structure.*/
    BOOLEAN Initialized;							/*This parameter indicates whether the data structure has been initialized or not.*/
    HANDLE SsHandle;								/*This parameter contains a handle to the heap in which the data structure is allocated.*/
    LIST_ENTRY InLoadOrderModuleList;				/*This parameter is a doubly-linked list that contains the DLLs in the order in which they were loaded into the process.*/
    LIST_ENTRY InMemoryOrderModuleList;				/*This parameter is a doubly-linked list that contains the DLLs in the order in which they are loaded into memory.*/
    LIST_ENTRY InInitializationOrderModuleList;		/*This parameter is a doubly-linked list that contains the DLLs in the order in which they are initialized.*/
    PVOID EntryInProgress;							/*This parameter is used by the operating system to track the initialization of DLLs. It points to the entry in one of the above linked lists that is currently being initialized.*/
    BOOLEAN ShutdownInProgress;						/*This parameter is used by the operating system to track the initialization of DLLs. It points to the entry in one of the above linked lists that is currently being initialized.*/
    HANDLE ShutdownThreadId;						/*This parameter contains the ID of the thread that is responsible for shutting down the process.*/
} PEB_LDR_DATA, * PPEB_LDR_DATA;
// https://processhacker.sourceforge.io/doc/struct___p_e_b___l_d_r___d_a_t_a.html

// The structure "_PEB" in the Windows operating system is a data structure that contains information about the current process.
// It is used by the operating system to manage and execute the process, as well as to provide access to various system resources and functions.
// The structure contains information such as the base address of the process, its size, and other details.
// It is also used by the operating system to store and retrieve data about the process, such as its environment,
//command-line arguments, and handles to various system objects.
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;									/*The "BeingDebugged" parameter in the _PEB struct indicates whether the process is being debugged by a debugger. This parameter is typically set to 1 if the process is being debugged, and 0 if it is not.*/

    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;									/*The "ImageBaseAddress" parameter in the _PEB struct indicates the base address of the process's executable image in memory. This is the starting address in memory where the process's executable code is loaded. The value of this parameter can be used, for example, to calculate the offsets of other data structures within the process's memory space.*/
    PPEB_LDR_DATA Ldr;										/*The "Ldr" parameter in the _PEB struct is a pointer to a data structure called the _PEB_LDR_DATA, which contains information about the dynamic linking process for the process.*/
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;			/*The "ProcessParameters" parameter in the _PEB struct is a pointer to a data structure called the _RTL_USER_PROCESS_PARAMETERS structure, which contains a variety of information about the process, including the command line arguments that were used to launch the process, the environment variables for the process, and the path to the process's current directory.*/
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, * PPEB;
// https://processhacker.sourceforge.io/doc/struct___p_e_b.html

// Totally undocumented 
typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// Totally undocumented 
typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// Totally undocumented
typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// Totally undocumented
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG ReferenceCount;
    ULONG DependencyCount;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
    ULONG LowestLink;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// Totally undocumented
typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// Totally undocumented, but understandable
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// The "LDR_DATA_TABLE_ENTRY" struct is used in the Windows operating system to store information about a loaded DLL (dynamic-link library).
// This struct is typically contained within the _PEB_LDR_DATA structure, which is part of the _PEB (Process Environment Block)
// data structure that is associated with each process in the system.
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;									/*The "DllBase" parameter in the "LDR_DATA_TABLE_ENTRY" struct is a pointer to the base address in memory where the DLL (dynamic-link library) is loaded. This is the starting address in memory where the DLL's code and data is loaded, and can be used to calculate offsets for other data structures within the DLL's memory space.*/
    PVOID EntryPoint;								/*The "EntryPoint" parameter in the "LDR_DATA_TABLE_ENTRY" struct is a pointer to the entry point of the DLL (dynamic-link library) in memory. The entry point is the starting address of the DLL's main code, which is executed when the DLL is loaded. This parameter can be used, for example, to determine where in memory the DLL's code starts, or to call the DLL's main function.*/
    ULONG SizeOfImage;								/*The "SizeOfImage" parameter in the "LDR_DATA_TABLE_ENTRY" struct indicates the size, in bytes, of the DLL (dynamic-link library) image in memory. This parameter can be used, for example, to determine the amount of memory that the DLL is using, or to verify that the DLL's image in memory is the expected size.*/
    UNICODE_STRING FullDllName;						/*The "FullDllName" parameter in the "LDR_DATA_TABLE_ENTRY" struct is a pointer to a UNICODE_STRING structure that contains the full path and file name of the DLL (dynamic-link library) on disk. This parameter can be used, for example, to determine the location of the DLL on disk, or to verify that the DLL that is loaded in memory is the expected DLL.*/
    UNICODE_STRING BaseDllName;						/*The "BaseDllName" parameter in the "LDR_DATA_TABLE_ENTRY" struct is a pointer to a UNICODE_STRING structure that contains the file name of the DLL (dynamic-link library) on disk, without the path. This parameter can be used, for example, to determine the name of the DLL, or to verify that the DLL that is loaded in memory is the expected DLL.*/
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html

// The "TEB" (Thread Environment Block) is a data structure that contains information about a thread in the Windows operating system.
// This structure is typically located at a fixed address in the thread's memory space, and can be accessed
// by the thread itself or by other components of the operating system.
typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;					/*The "ProcessEnvironmentBlock" parameter in the "TEB" (Thread Environment Block) struct is a pointer to the _PEB (Process Environment Block) data structure that is associated with the thread's process.*/

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
    UCHAR SpareBytes[24];
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
    PVOID Instrumentation[11];
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT SpareSameTebBits : 4;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
} TEB, * PTEB;
// https://processhacker.sourceforge.io/doc/struct___t_e_b.html

// This structure specifies attributes that can be applied to objects or object handles
// by routines that create objects and/or return handles to objects.
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;					/*The number of bytes of data contained in this structure.*/
    HANDLE RootDirectory;			/*Optional handle to the root object directory for the path name specified by the ObjectName member. If RootDirectory is NULL, ObjectName must point to a fully qualified object name that includes the full path to the target object. If RootDirectory is non-NULL, ObjectName specifies an object name relative to the RootDirectory directory. The RootDirectory handle can refer to a file system directory or an object directory in the object manager namespace.*/
    PUNICODE_STRING ObjectName;		/*Pointer to a Unicode string that contains the name of the object for which a handle is to be opened. This must either be a fully qualified object name, or a relative path name to the directory specified by the RootDirectory member.*/
    ULONG Attributes;				/*Bitmask of flags that specify object handle attributes.*/
    PVOID SecurityDescriptor;		/*Specifies a security descriptor (SECURITY_DESCRIPTOR) for the object when the object is created. If this member is NULL, the object will receive default security settings.*/
    PVOID SecurityQualityOfService; /*Optional quality of service to be applied to the object when it is created. Used to indicate the security impersonation level and context tracking mode (dynamic or static).*/
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186

// The _SECTION_INHERIT structure is a type of data structure used in the Windows operating system
// to store information about the inheritance of memory sections within a process.
typedef enum _SECTION_INHERIT {
	ViewShare = 1,					/*Created view of Section Object will be also mapped to any created in future process.*/
	ViewUnmap = 2					/*Created view will not be inherited by child processes.*/
} SECTION_INHERIT, * PSECTION_INHERIT;
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html

//// The purpose of the TYPEOFFSET structure, and the corresponding relocation entries
//// in a PE file, is to specify the locations of code and data items that need to be fixed up
//// (i.e., relocated) when the PE file is loaded into memory. 
//typedef struct _TYPEOFFSET {
//	WORD	Type:4;                 /*A 4-bit value that specifies the type of relocation that needs to be applied to the item.*/
//	WORD	Offset:12;              /*A 12-bit value that specifies the offset of the code or data item that needs to be relocated, relative to the beginning of the section where it is located*/
//} TYPEOFFSET, *PTYPEOFFSET;
//// OpenAI

// The IO_STATUS_BLOCK structure is used to receive the completion status of an I/O operation when it completes.
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;            /*An NTSTATUS value that indicates the success or failure of an I/O operation.*/
        PVOID    Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;          /*: A value that specifies the number of bytes transferred during an I/O operation, or other information about the operation. The meaning of this value depends on the specific I/O operation being performed.*/
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
