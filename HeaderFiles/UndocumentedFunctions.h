#pragma once
#include <windows.h>
#include "UndocumentedStruct.h"

// Allows to dynamically load a DLL (Dynamic Link Library) at runtime.
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
	PCWSTR      PathToFile,					/*Optional*/
	ULONG       Flags,						/*Optional*/
	PUNICODE_STRING  ModuleFileName,		/*A pointer to a UNICODE_STRING structure that contains the filename of the DLL*/
	PHANDLE     ModuleHandle				/*A pointer to a variable that receives the handle to the DLL.*/
);
// The function returns an NTSTATUS value indicating the success or failure of the operation.
// OpenAI

// The NtAllocateVirtualMemory routine reserves, commits, or both,
// a region of pages within the user-mode virtual address space of a specified process.
typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE ProcessHandle,					/*A handle to the process in which the memory will be allocated.*/
	PVOID* BaseAddress,						/*A pointer to a variable that specifies the base address at which the memory region should be allocated. The function will update this variable with the actual base address of the allocated memory region.*/
	ULONG_PTR ZeroBits,						/*The number of high-order address bits that must be zero in the base address*/
	PSIZE_T RegionSize,						/*A pointer to a variable that specifies the size of the memory region to be allocated. The function will update this variable with the actual size of the allocated memory region.*/
	ULONG AllocationType,					/*A flag that specifies the type of allocation to be performed.*/
	ULONG Protect							/*The protection attributes for the allocated memory region.*/
);
// The function returns an NTSTATUS value that indicates the success or failure of the operation.
// If the function succeeds, it returns STATUS_SUCCESS and updates the BaseAddress and RegionSize variables
// with the actual base address and size of the allocated memory region.
// If the function fails, it returns an error code indicating the reason for the failure.
// OpenAI

// Creates a Section Object (virtual memory block with associated file).
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
	OUT PHANDLE					   SectionHandle,			/*A pointer to a variable that will receive the handle to the newly created section object.*/
	IN ULONG					   DesiredAccess,			/*Specifies the access rights that the calling process will have to the new section object.*/
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,		/*A pointer to a SECURITY_ATTRIBUTES structure that specifies the security attributes for the new section object.*/
	IN OPTIONAL PLARGE_INTEGER	   MaximumSize,				/*Specifies the maximum size of the section object, in bytes.*/
	IN ULONG				       PageAttributess,			/*Specifies the memory protection for the pages of the section object.*/
	IN ULONG					   SectionAttributes,		/*Specifies the allocation attributes for the section object, such as whether it should be reserved or committed.*/
	IN OPTIONAL HANDLE			   FileHandle);				/*A handle to the file or device that will be mapped into the section object.*/
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html

// Creates a new thread in the local or a remote process
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,					/*A pointer to a variable that will receive the handle to the new thread*/
	IN ACCESS_MASK DesiredAccess,			/*Specifies the access rights that the calling process will have to the new thread.*/
	IN PVOID ObjectAttributes,				/*A pointer to a SECURITY_ATTRIBUTES structure that specifies the security attributes for the new thread.*/
	IN HANDLE ProcessHandle,				/*A handle to the process in which the new thread will be created.*/
	IN PVOID lpStartAddress,				/*A pointer to the function that will be executed when the new thread is started.*/
	IN PVOID lpParameter,					/*A pointer to a block of data that will be passed as a parameter to the thread function when it is called.*/
	IN ULONG Flags,							/*Specifies whether the new thread should be created in a suspended state, in which case it will not start executing until resumed.*/
	IN SIZE_T StackZeroBits,				/*Specifies the size of the stack for the new thread, in terms of the number of zero bits in the stack pointer.*/
	IN SIZE_T SizeOfStackCommit,			/*Specifies the size of the initial committed stack, in bytes.*/
	IN SIZE_T SizeOfStackReserve,			/*Specifies the size of the reserved stack, in bytes.*/
	OUT PVOID lpBytesBuffer);				/*A pointer to a buffer that will be used to store information about the new thread, such as its thread ID.*/
// Returns an NTSTATUS code indicating the success or failure of the operation.
// OpenAI

//// Flush the instruction cache for a given memory region on a computer running the Windows operating system.
//typedef NTSTATUS(NTAPI* NtFlushInstructionCache_t)(
//	HANDLE  ProcessHandle,					/*A handle to the process whose instruction cache is to be flushed.*/
//	PVOID   BaseAddress,					/*A pointer to the base address of the memory region to be flushed.*/
//	SIZE_T  NumberOfBytesToFlush			/*A pointer to the base address of the memory region to be flushed.*/
//);
//// If the function succeeds, the return value is STATUS_SUCCESS.
//// Otherwise, the return value is an error code.
//// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtFlushInstructionCache.html

// Allows to retrieve the context of a thread.
// The context of a thread includes the current values of the thread's registers,
// as well as certain other information about the thread's execution state.
typedef NTSTATUS(NTAPI* NtGetContextThread_t)(
	HANDLE ThreadHandle,					/*A handle to the thread whose context is to be retrieved. The handle must have the THREAD_QUERY_INFORMATION access right.*/
	PCONTEXT ThreadContext					/*A pointer to a CONTEXT structure that receives the context of the specified thread.*/
);
// The function returns an NTSTATUS code indicating the status of the operation.
// OpenAI

// Maps a view of a section into the virtual address space of a subject process.
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
	IN HANDLE SectionHandle,				/*A handle to the section object that will be mapped into the virtual address space of the process.*/
	IN HANDLE ProcessHandle,				/*A handle to the process in which the section object will be mapped.*/
	IN OUT PVOID* BaseAddress,				/*A pointer to a variable that specifies the base address where the section object will be mapped, or NULL if the system should choose the base address automatically.*/
	IN ULONG_PTR ZeroBits,					/*Specifies the number of high-order address bits that must be zero in the base address of the mapped view.*/
	IN SIZE_T CommitSize,					/*Specifies the size of the initial committed region of the mapped view, in bytes.*/
	IN OUT PLARGE_INTEGER SectionOffset,	/*Specifies the offset within the section object where the mapping will start, in bytes*/
	IN PSIZE_T ViewSize,					/*A pointer to a variable that will receive the actual size of the mapped view, in bytes.*/
	IN DWORD InheritDisposition,			/*Specifies the inheritance disposition of the view.*/
	IN ULONG AllocationType,				/*Specifies the type of allocation for the view.*/
	IN ULONG Win32Protect);					/*Specifies the protection for the view.*/
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html

// It opens a handle to a process with a specified access mask.
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
	PHANDLE ProcessHandle,					/*A pointer to a variable that will receive the handle to the process.*/
	ACCESS_MASK DesiredAccess,				/*The access rights that the caller wants to the process.*/
	POBJECT_ATTRIBUTES ObjectAttributes,	/*A pointer to an OBJECT_ATTRIBUTES structure that specifies the attributes of the process object.*/
	PCLIENT_ID ClientId						/*A pointer to a CLIENT_ID structure that specifies the identifier of the process to open.*/
);
// OpenAI

// NtProtectVirtualMemory is a function in the Windows operating system that is used to change the protection attributes
// of a region of memory within the virtual address space of a process.
typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_t)(
	HANDLE ProcessHandle,					/*A handle to the process whose virtual address space the memory belongs to.*/
	PVOID* BaseAddress,						/*A pointer to a variable that specifies the base address of the memory region. The function will update this variable with the actual base address of the memory region.*/
	PSIZE_T RegionSize,						/*A pointer to a variable that specifies the size of the memory region. The function will update this variable with the actual size of the memory region.*/
	ULONG NewProtect,						/*The new protection attributes for the memory region.*/
	PULONG OldProtect						/*The new protection attributes for the memory region.*/
);
// The function returns an NTSTATUS value that indicates the success or failure of the operation.
// If the function succeeds, it returns STATUS_SUCCESS and updates the protection attributes of the memory region.
// If the function fails, it returns an error code indicating the reason for the failure.
// OpenAI

// Allows one thread to execute an Asynchronous Procedure Call (APC) on another thread.
typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
	HANDLE               ThreadHandle,			/*A handle to the thread on which the APC is to be executed. The handle must have the THREAD_SET_CONTEXT access right.*/
	PVOID                ApcRoutine,			/*A pointer to the APC function to be executed.*/
	PVOID                ApcRoutineContext,		/*A pointer to a user-defined context value that is passed to the APC function when it is executed.*/
	PIO_STATUS_BLOCK     ApcStatusBlock,		/*A pointer to an IO_STATUS_BLOCK structure that receives the completion status of the APC function. This parameter can be NULL if the status is not required.*/
	ULONG                ApcReserved			/*A reserved parameter that must be set to zero.*/
);
// Returns an NTSTATUS value indicating the success or failure of the operation.
// OpenAI

// Allows to read the memory of a process in Windows
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
	HANDLE  ProcessHandle,						/*A handle to the process whose memory you want to read.*/
	PVOID   BaseAddress,						/*A pointer to the base address of the memory to read in the target process. This address should be valid and accessible within the target process.*/
	PVOID   Buffer,								/*A pointer to a buffer that will receive the memory contents read from the target process.*/
	SIZE_T  NumberOfBytesToRead,				/*The number of bytes to read from the target process's memory.*/
	PSIZE_T NumberOfBytesRead					/* A pointer to a variable that will receive the number of bytes actually read from the target process's memory.*/
);
// Returns an NTSTATUS value indicating the success or failure of the operation.
// OpenAI

// Resumes execution of a suspended thread.
typedef NTSTATUS(NTAPI* NtResumeThread_t)(
	HANDLE ThreadHandle,						/*A handle to the thread to be resumed. The handle must have the THREAD_SUSPEND_RESUME access right.*/
	PULONG SuspendCount							/*A pointer to a variable that receives the previous suspend count of the thread. If the thread was not previously suspended, the suspend count is zero.*/
);
// OpenAI

// Allows to set the context of a thread.
// The context of a thread refers to the state of the thread's registers and the kernel stack when the thread is executing.
typedef NTSTATUS(NTAPI* NtSetContextThread_t)(
	HANDLE ThreadHandle,						/*A handle to the thread whose context is to be set. The handle must have the THREAD_SET_CONTEXT access right.*/
	PCONTEXT ThreadContext						/*A pointer to a CONTEXT structure that specifies the new context of the specified thread. The CONTEXT structure contains a set of processor-specific registers and other state information.*/
);
// The function returns an NTSTATUS code indicating the status of the operation.
// OpenAI


// Allows to suspend a thread.
// When a thread is suspended, it is temporarily stopped from executing and will not be scheduled for execution until it is resumed.
typedef NTSTATUS(NTAPI* NtSuspendThread_t)(
	HANDLE ThreadHandle,						/*A handle to the thread that is to be suspended. The handle must have the THREAD_SUSPEND_RESUME access right.*/
	PULONG PreviousSuspendCount					/*A pointer to a variable that receives the previous suspend count for the specified thread. If the function succeeds, the variable receives the previous suspend count. If the function fails, the variable is not updated.*/
);
// The function returns an NTSTATUS code indicating the status of the operation.
// OpenAI

//// Waits for a specified object to become signaled, or for a specified time interval to elapse.
//typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(
//	HANDLE Handle,							/*A handle to the object to wait on.*/
//	BOOLEAN Alertable,						/*If this value is TRUE, NtWaitForSingleObject will return if an APC is delivered to the thread. If it is FALSE, NtWaitForSingleObject will not return until the object becomes signaled or the timeout interval elapses.*/
//	PLARGE_INTEGER Timeout					/*A pointer to a LARGE_INTEGER structure that specifies the timeout interval, in 100-nanosecond units. If this parameter is NULL, NtWaitForSingleObject will wait indefinitely.*/
//);
//// OpenAI

// Allows a program to write to the virtual memory of another process.
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,					/*A handle to the process whose memory is to be written. This handle must have the PROCESS_VM_WRITE access right.*/
	PVOID BaseAddress,						/*A pointer to the base address in the process's virtual address space to which the write operation is to be performed.*/
	PVOID Buffer,							/*A pointer to a buffer containing the data to be written.*/
	SIZE_T BufferSize,						/*The size of the buffer, in bytes.*/
	PSIZE_T NumberOfBytesWritten			/*A pointer to a variable that will receive the number of bytes actually written.*/
);
// Returns an NTSTATUS code indicating the success or failure of the operation.
// OpenAI

// Allows a program to request a block of memory from the heap
typedef PVOID(NTAPI* RtlAllocateHeap_t)(
	HANDLE  hHeap,					/*This is a handle to the heap from which the memory will be allocated.*/
	ULONG   dwFlags,				/*This is a set of flags that control the behavior of the RtlAllocateHeap function. Some of the possible values for this argument include HEAP_ZERO_MEMORY, which causes the function to zero-initialize the memory block, and HEAP_GENERATE_EXCEPTIONS, which causes the function to raise an exception if the memory cannot be allocated.*/
	SIZE_T  dwBytes					/*This is the size of the memory block to be allocated, in bytes.*/
);
// The function returns a pointer to the allocated memory block, or NULL if the memory could not be allocated.
// OpenAI

//// It appends the contents of the Source UNICODE_STRING to the end of the Destination UNICODE_STRING.
//// The Destination UNICODE_STRING must have enough space to hold the concatenated strings.
//// The Source UNICODE_STRING is not modified.
//typedef VOID(NTAPI* RtlAppendUnicodeStringToString_t)(
//	IN PUNICODE_STRING Destination,
//	IN PUNICODE_STRING Source
//);
//
//// Undocumented API to create a thread in the current or a remote process
//typedef NTSTATUS(NTAPI* RtlCreateUserThread_t)(
//	IN HANDLE						 ProcessHandle,						/*A handle to the process in which the thread will be created.*/
//	IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,				/*A pointer to a security descriptor that specifies the access rights for the thread.*/
//	IN BOOLEAN						 CreateSuspended,					/*A flag that specifies whether the thread should be created in a suspended state, where it will not execute until resumed.*/
//	IN ULONG						 StackZeroBits,						/*The number of high-order bits of the thread's initial stack that should be set to zero.*/
//	IN OUT PULONG					 StackReserved,						/*The maximum size of the thread's stack.*/
//	IN OUT PULONG					 StackCommit,						/*Specifies the initial amount of memory, in bytes, to be committed to the stack of the new thread.*/
//	IN PVOID						 StartAddress,						/*A pointer to the function that the thread should execute when it begins.*/
//	IN OPTIONAL PVOID				 StartParameter,					/*A pointer to an argument that will be passed to the thread's start function.*/
//	OUT PHANDLE						 ThreadHandle,						/*A pointer to a variable that receives the handle to the new thread.*/
//	OUT PCLIENT_ID					 ClientID);							/*A pointer to a variable that receives the thread's client ID, which consists of a thread ID and a process ID.*/
//// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
//
//typedef BOOLEAN(NTAPI* RtlFreeHeap_t)(
//	HANDLE  hHeap,				/*This is a handle to the heap from which the memory was allocated.*/
//	ULONG   dwFlags,			/*his is a set of flags that control the behavior of the RtlFreeHeap function. Some of the possible values for this argument include HEAP_NO_SERIALIZE, which tells the function not to acquire a lock on the heap, and HEAP_GENERATE_EXCEPTIONS, which causes the function to raise an exception if the memory block cannot be freed.*/
//	PVOID   lpMem				/*This is a pointer to the memory block to be freed.*/
//);
//// The function returns TRUE if the memory was successfully freed,
//// or FALSE if the memory could not be freed.
//// OpenAI

// It initializes a Unicode string structure with the specified string.
typedef VOID (NTAPI* RtlInitUnicodeString_t)(
	PUNICODE_STRING DestinationString,		/*The structure that will be initialized.*/
	PCWSTR          SourceString			/*A pointer to a null-terminated string that will be used to initialize the UNICODE_STRING structure.*/
);
// OpenAI

// Copies the contents of a source memory block to a destination memory block,
// and supports overlapping source and destination memory blocks.
typedef VOID(NTAPI* RtlMoveMemory_t)(
	OUT VOID UNALIGNED* Destination,			/*A pointer to the destination memory block to copy the bytes to.*/
	IN  const VOID UNALIGNED* Source,			/*A pointer to the source memory block to copy the bytes from.*/
	IN  SIZE_T Length							/*The number of bytes to copy from the source to the destination.*/
);
// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory

// The RtlZeroMemory routine fills a block of memory with zeros, given a pointer to the block and the length, in bytes, to be filled.
typedef void(NTAPI* RtlZeroMemory_t)(
	void* Destination,						/*A pointer to the memory block to be filled with zeros.*/
	size_t Length							/*The number of bytes to fill with zeros.*/
);
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlzeromemory