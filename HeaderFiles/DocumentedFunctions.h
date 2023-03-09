#pragma once
#include <windows.h>
#include <tlhelp32.h>

// Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(
	IN DWORD dwFlags,							/*The portions of the system to be included in the snapshot.*/
	IN DWORD th32ProcessID						/*The process identifier of the process to be included in the snapshot. This parameter can be zero to indicate the current process. This parameter is used when the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, or TH32CS_SNAPALL value is specified. Otherwise, it is ignored and all processes are included in the snapshot.*/
	);
// If the function succeeds, it returns an open handle to the specified snapshot.
// If the function fails, it returns INVALID_HANDLE_VALUE.
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot

// Creates a new process and its primary thread. The new process runs in the security context of the calling process.
typedef BOOL(WINAPI* CreateProcessA_t)(
	IN OPTIONAL     LPCSTR                lpApplicationName,		/*The name of the module to be executed.*/
	IN OUT OPTIONAL LPSTR                 lpCommandLine,			/*The command line to be executed. The lpCommandLine parameter can be NULL. In that case, the function uses the string pointed to by lpApplicationName as the command line.*/
	IN OPTIONAL     LPSECURITY_ATTRIBUTES lpProcessAttributes,		/*A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is NULL, the handle cannot be inherited.*/
	IN OPTIONAL     LPSECURITY_ATTRIBUTES lpThreadAttributes,		/*A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle to the new thread object can be inherited by child processes. If lpThreadAttributes is NULL, the handle cannot be inherited.*/
	IN              BOOL                  bInheritHandles,			/*If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process. If the parameter is FALSE, the handles are not inherited.*/
	IN              DWORD                 dwCreationFlags,			/*The flags that control the priority class and the creation of the process.*/
	IN OPTIONAL     LPVOID                lpEnvironment,			/*A pointer to the environment block for the new process. If this parameter is NULL, the new process uses the environment of the calling process.*/
	IN OPTIONAL     LPCSTR                lpCurrentDirectory,		/*The full path to the current directory for the process. The string can also specify a UNC path. If this parameter is NULL, the new process will have the same current drive and directory as the calling process. */
	IN              LPSTARTUPINFOA        lpStartupInfo,			/*A pointer to a STARTUPINFO or STARTUPINFOEX structure.*/
	OUT             LPPROCESS_INFORMATION lpProcessInformation		/*A pointer to a PROCESS_INFORMATION structure that receives identification information about the new process.*/
);
// If the function succeeds, the return value is nonzero.
// If the function fails, the return value is zero.
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

//// Creates a thread that runs in the virtual address space of another process.
//typedef HANDLE(WINAPI* CreateRemoteThread_t)(
//	IN  HANDLE                 hProcess,				/*A handle to the process in which the thread is to be created. The handle must have the PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ access rights, and may fail without these rights on certain platforms.*/
//	IN  LPSECURITY_ATTRIBUTES  lpThreadAttributes,		/*A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited.*/
//	IN  SIZE_T                 dwStackSize,				/*The initial size of the stack, in bytes.*/
//	IN  LPTHREAD_START_ROUTINE lpStartAddress,			/*A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process. The function must exist in the remote process.*/
//	IN  LPVOID                 lpParameter,				/*A pointer to a variable to be passed to the thread function.*/
//	IN  DWORD                  dwCreationFlags,			/*The flags that control the creation of the thread.*/
//	OUT LPDWORD                lpThreadId				/*A pointer to a variable that receives the thread identifier. If this parameter is NULL, the thread identifier is not returned.*/
//);
//// If the function succeeds, the return value is a handle to the new thread.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
//
//// Creates a thread to execute within the virtual address space of the calling process.
//typedef HANDLE(WINAPI* CreateThread_t)(
//  IN OPTIONAL  LPSECURITY_ATTRIBUTES   lpThreadAttributes,		/*A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle can be inherited by child processes. If lpThreadAttributes is NULL, the handle cannot be inherited.*/
//  IN           SIZE_T                  dwStackSize,				/*The initial size of the stack, in bytes.*/
//  IN           LPTHREAD_START_ROUTINE  lpStartAddress,			/*A pointer to the application-defined function to be executed by the thread. This pointer represents the starting address of the thread.*/
//  IN OPTIONAL  __drv_aliasesMem LPVOID lpParameter,				/*A pointer to a variable to be passed to the thread.*/
//  IN           DWORD                   dwCreationFlags,			/*The flags that control the creation of the thread.*/
//  OUT OPTIONAL LPDWORD                 lpThreadId				/*A pointer to a variable that receives the thread identifier. If this parameter is NULL, the thread identifier is not returned.*/
//);
//// If the function succeeds, the return value is a handle to the new thread.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

// Closes an open object handle.
typedef BOOL(WINAPI* CloseHandle_t)(
	IN HANDLE hObject							/*A valid handle to an open object.*/
);
// If the function succeeds, the return value is nonzero.
// If the function fails, the return value is zero.
// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle

// Determines the location of a resource with the specified type and name in the specified module.
typedef HRSRC(WINAPI* FindResourceA_t)(
  IN OPTIONAL HMODULE  hModule,					/*A handle to the module whose portable executable file or an accompanying MUI file contains the resource. If this parameter is NULL, the function searches the module used to create the current process.*/
  IN          LPCSTR  lpName,					/*The name of the resource. Alternately, rather than a pointer, this parameter can be MAKEINTRESOURCE(ID), where ID is the integer identifier of the resource.*/
  IN          LPCSTR  lpType					/*The resource type. Alternately, rather than a pointer, this parameter can be MAKEINTRESOURCE(ID), where ID is the integer identifier of the given resource type.*/
);
// If the function succeeds, the return value is a handle to the specified resource's information block.
// To obtain a handle to the resource, pass this handle to the LoadResource function.
// If the function fails, the return value is NULL.
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findresourcea

//// Retrieves a pseudo handle for the current process.
//typedef HANDLE(WINAPI* GetCurrentProcess_t)();
//// The return value is a pseudo handle to the current process.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
//
//// Retrieves the address of an exported function (also known as a procedure)
//// or variable from the specified dynamic-link library (DLL).
//typedef FARPROC(WINAPI* GetProcAddress_t)(
//  IN HMODULE hModule,							/*A handle to the DLL module that contains the function or variable.*/
//  IN LPCSTR  lpProcName							/*The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.*/
//);
//// If the function succeeds, the return value is the address of the exported function or variable.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
//
//// Retrieves the context of the specified thread.
//typedef BOOL(WINAPI* GetThreadContext_t)(
//	IN     HANDLE    hThread,					/*A handle to the thread whose context is to be retrieved. The handle must have THREAD_GET_CONTEXT access to the thread.*/
//	IN OUT LPCONTEXT lpContext					/*A pointer to a CONTEXT structure (such as ARM64_NT_CONTEXT) that receives the appropriate context of the specified thread. The value of the ContextFlags member of this structure specifies which portions of a thread's context are retrieved.*/
//);
//// If the function succeeds, the return value is nonzero.
//// If the function fails, the return value is zero.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext

// Closes a single Internet handle.
typedef BOOL(WINAPI* InternetCloseHandle_t)(
	IN HANDLE hInternet							/*Handle to be closed.*/
);
// Returns TRUE if the handle is successfully closed, or FALSE otherwise.
// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle

// Initializes an application's use of the WinINet functions.
typedef HANDLE(WINAPI* InternetOpenA_t)(
	IN LPCSTR lpszAgent,						/*Pointer to a null-terminated string that specifies the name of the application or entity calling the WinINet functions. This name is used as the user agent in the HTTP protocol.*/
	IN DWORD  dwAccessType,						/*Type of access required. This parameter can be one of the following values.*/
	IN LPCSTR lpszProxy,						/*Pointer to a null-terminated string that specifies the name of the proxy server(s) to use when proxy access is specified by setting dwAccessType to INTERNET_OPEN_TYPE_PROXY.*/
	IN LPCSTR lpszProxyBypass,					/*Pointer to a null-terminated string that specifies an optional list of host names or IP addresses, or both, that should not be routed through the proxy when dwAccessType is set to INTERNET_OPEN_TYPE_PROXY.*/
	IN DWORD  dwFlags							/*Options.*/
);
// Returns a valid handle that the application passes to subsequent WinINet functions.
// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena

// Opens a resource specified by a complete FTP or HTTP URL.
typedef HANDLE(WINAPI* InternetOpenUrlA_t)(
	IN HANDLE     hInternet,						/*The handle to the current Internet session. The handle must have been returned by a previous call to InternetOpen.*/
	IN LPCSTR    lpszUrl,						/*A pointer to a null-terminated string variable that specifies the URL to begin reading. Only URLs beginning with ftp:, http:, or https: are supported.*/
	IN LPCSTR    lpszHeaders,					/*A pointer to a null-terminated string that specifies the headers to be sent to the HTTP server.*/
	IN DWORD     dwHeadersLength,				/*The size of the additional headers, in TCHARs.*/
	IN DWORD     dwFlags,						/*Options*/
	IN DWORD_PTR dwContext						/*A pointer to a variable that specifies the application-defined value that is passed, along with the returned handle, to any callback functions.*/
);
// Returns a valid handle to the URL if the connection is successfully established, or NULL if the connection fails.
// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurla

// Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function.
typedef BOOL(WINAPI* InternetReadFile_t)(
	IN  HANDLE    hFile,						/*Handle returned from a previous call to InternetOpenUrl, FtpOpenFile, or HttpOpenRequest.*/
	OUT LPVOID    lpBuffer,						/*Pointer to a buffer that receives the data.*/
	IN  DWORD     dwNumberOfBytesToRead,		/*Number of bytes to be read.*/
	OUT LPDWORD   lpdwNumberOfBytesRead			/*Pointer to a variable that receives the number of bytes read. InternetReadFile sets this value to zero before doing any work or error checking.*/
);
// Returns TRUE if successful, or FALSE otherwise.
// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile

//// Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.
//typedef HMODULE(WINAPI* LoadLibraryA_t)(
//  IN LPCSTR lpLibFileName						/*The name of the module. This can be either a library module (a .dll file) or an executable module (an .exe file).*/
//);
//// If the function succeeds, the return value is a handle to the module.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya

// Retrieves a handle that can be used to obtain a pointer to the first byte of the specified resource in memory.
typedef HGLOBAL(WINAPI* LoadResource_t)(
  IN OPTIONAL HMODULE hModule,					/*A handle to the module whose executable file contains the resource. If hModule is NULL, the system loads the resource from the module that was used to create the current process.*/
  IN          HRSRC   hResInfo					/*A handle to the resource to be loaded. This handle is returned by the FindResource or FindResourceEx function.*/
);
// If the function succeeds, the return value is a handle to the data associated with the resource.
// If the function fails, the return value is NULL.
// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource

// Retrieves a pointer to the specified resource in memory.
typedef LPVOID(WINAPI* LockResource_t)(
  IN HGLOBAL hResData							/*A handle to the resource to be accessed. The LoadResource function returns this handle.*/
);
// If the loaded resource is available, the return value is a pointer to the first byte of the resource; otherwise, it is NULL.
// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource

//// Opens an existing local process object.
//typedef HANDLE(WINAPI* OpenProcess_t)(
//	IN DWORD dwDesiredAccess,					/*The access to the process object. This access right is checked against the security descriptor for the process.*/
//	IN BOOL  bInheritHandle,					/*If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.*/
//	IN DWORD dwProcessId						/*The identifier of the local process to be opened.*/
//);
//// If the function succeeds, the return value is an open handle to the specified process.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

// Opens an existing thread object.
typedef HANDLE(WINAPI* OpenThread_t)(
	IN DWORD dwDesiredAccess,					/*The access to the thread object. This access right is checked against the security descriptor for the thread.*/
	IN BOOL  bInheritHandle,					/*If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.*/
	IN DWORD dwThreadId							/*The identifier of the thread to be opened.*/
);
// If the function succeeds, the return value is an open handle to the specified thread.
// If the function fails, the return value is NULL.
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread

//// Retrieves information about the first process encountered in a system snapshot.
//typedef BOOL(WINAPI* Process32First_t)(
//	IN     HANDLE           hSnapshot,			/*A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.*/
//	IN OUT LPPROCESSENTRY32 lppe				/*A pointer to a PROCESSENTRY32 structure.*/
//);
//// Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
//// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first

// Retrieves information about the next process recorded in a system snapshot.
typedef BOOL(WINAPI* Process32Next_t)(
	IN  HANDLE           hSnapshot,				/*A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.*/
	OUT LPPROCESSENTRY32 lppe					/*A pointer to a PROCESSENTRY32 structure.*/
);
// Returns TRUE if the next entry of the process list has been copied to the buffer or FALSE otherwise.
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

//// Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread.
//typedef DWORD(WINAPI* QueueUserAPC_t)(
//	IN PAPCFUNC  pfnAPC,						/*A pointer to the application-supplied APC function to be called when the specified thread performs an alertable wait operation.*/
//	IN HANDLE    hThread,						/*A handle to the thread. The handle must have the THREAD_SET_CONTEXT access right.*/
//	IN ULONG_PTR dwData							/*A single value that is passed to the APC function pointed to by the pfnAPC parameter.*/
//);
//// If the function succeeds, the return value is nonzero. If the function fails, the return value is zero.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
//
//// Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.
//typedef DWORD(WINAPI* ResumeThread_t)(
//	IN HANDLE hThread							/*A handle to the thread to be restarted.*/
//);
//// If the function succeeds, the return value is the thread's previous suspend count.
//// If the function fails, the return value is(DWORD) - 1.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
//
//// Sets the context for the specified thread.
//typedef BOOL(WINAPI* SetThreadContext_t)(
//	IN HANDLE        hThread,					/*A handle to the thread whose context is to be set. The handle must have the THREAD_SET_CONTEXT access right to the thread.*/
//	IN const CONTEXT* lpContext					/*A pointer to a CONTEXT structure that contains the context to be set in the specified thread. The value of the ContextFlags member of this structure specifies which portions of a thread's context to set. Some values in the CONTEXT structure that cannot be specified are silently set to the correct value. This includes bits in the CPU status register that specify the privileged processor mode, global enabling bits in the debugging register, and other states that must be controlled by the operating system.*/
//);
//// If the context was set, the return value is nonzero.
//// If the function fails, the return value is zero.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext

// Retrieves the size, in bytes, of the specified resource.
typedef DWORD(WINAPI* SizeofResource_t)(
  IN OPTIONAL HMODULE hModule,					/*A handle to the module whose executable file contains the resource. Default is the module used to create the current process.*/
  IN          HRSRC   hResInfo					/*A handle to the resource. This handle must be created by using the FindResource or FindResourceEx function.*/
);
// If the function succeeds, the return value is the number of bytes in the resource.
// If the function fails, the return value is zero.
// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource

//// Suspends the execution of the current thread until the time-out interval elapses.
//typedef void(WINAPI* Sleep_t)(
//	IN DWORD dwMilliseconds						/*The time interval for which execution is to be suspended, in milliseconds.*/
//);
//// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
//
//// Suspends the specified thread.
//typedef DWORD(WINAPI* SuspendThread_t)(
//	IN HANDLE hThread							/*A handle to the thread that is to be suspended. The handle must have the THREAD_SUSPEND_RESUME access right.*/
//);
//// If the function succeeds, the return value is the thread's previous suspend count; otherwise, it is (DWORD) -1.
//// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread

// Retrieves information about the next thread of any process encountered in the system memory snapshot.
typedef BOOL(WINAPI* Thread32Next_t)(
	IN  HANDLE          hSnapshot,				/*A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.*/
	OUT LPTHREADENTRY32 lpte					/*A pointer to a THREADENTRY32 structure.*/
);
// Returns TRUE if the next entry of the thread list has been copied to the buffer or FALSE otherwise.
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next

//// Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.
//// Memory allocated by this function is automatically initialized to zero.
//typedef LPVOID(WINAPI* VirtualAlloc_t)(
//	IN OPTIONAL LPVOID lpAddress,				/*The starting address of the region to allocate. If this parameter is NULL, the system determines where to allocate the region.*/
//	IN          SIZE_T dwSize,					/*The size of the region, in bytes. If the lpAddress parameter is NULL, this value is rounded up to the next page boundary.*/
//	IN          DWORD  flAllocationType,		/*The type of memory allocation.*/
//	IN          DWORD  flProtect				/*The memory protection for the region of pages to be allocated.*/
//);
//// If the function succeeds, the return value is the base address of the allocated region of pages.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
//
//// Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process.
//// The function initializes the memory it allocates to zero.
//typedef LPVOID(WINAPI* VirtualAllocEx_t)(
//	IN          HANDLE hProcess,				/*The handle to a process. The function allocates memory within the virtual address space of this process. The handle must have the PROCESS_VM_OPERATION access right.*/
//	IN OPTIONAL LPVOID lpAddress,				/*The pointer that specifies a desired starting address for the region of pages that you want to allocate. If lpAddress is NULL, the function determines where to allocate the region.*/
//	IN			SIZE_T dwSize,					/*The size of the region of memory to allocate, in bytes.*/
//	IN			DWORD  flAllocationType,		/*The type of memory allocation.*/
//	IN			DWORD  flProtect				/*The memory protection for the region of pages to be allocated.*/
//);
//// If the function succeeds, the return value is the base address of the allocated region of pages.
//// If the function fails, the return value is NULL.
//// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
//
//// Changes the protection on a region of committed pages in the virtual address space of the calling process.
//typedef BOOL(WINAPI* VirtualProtect_t)(
//	IN  LPVOID lpAddress,						/*The address of the starting page of the region of pages whose access protection attributes are to be changed.*/
//	IN  SIZE_T dwSize,							/*The size of the region whose access protection attributes are to be changed, in bytes. The region of affected pages includes all pages containing one or more bytes in the range from the lpAddress parameter to (lpAddress+dwSize).*/
//	IN  DWORD  flNewProtect,					/*The memory protection option.*/
//	OUT PDWORD lpflOldProtect					/*A pointer to a variable that receives the previous access protection value of the first page in the specified region of pages. If this parameter is NULL or does not point to a valid variable, the function fails.*/
//);
//// If the function succeeds, the return value is nonzero.
//// If the function fails, the return value is zero.
//// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
//
//// Changes the protection on a region of committed pages in the virtual address space of a specified process.
//typedef BOOL(WINAPI* VirtualProtectEx_t)(
//	IN  HANDLE hProcess,						/*A handle to the process whose memory protection is to be changed. The handle must have the PROCESS_VM_OPERATION access right.*/
//	IN  LPVOID lpAddress,						/*A pointer to the base address of the region of pages whose access protection attributes are to be changed.*/
//	IN  SIZE_T dwSize,							/*The size of the region whose access protection attributes are changed, in bytes. The region of affected pages includes all pages containing one or more bytes in the range from the lpAddress parameter to (lpAddress+dwSize).*/
//	IN  DWORD  flNewProtect,					/*The memory protection option.*/
//	OUT PDWORD lpflOldProtect					/*A pointer to a variable that receives the previous access protection of the first page in the specified region of pages. If this parameter is NULL or does not point to a valid variable, the function fails.*/
//);
//// If the function succeeds, the return value is nonzero.
//// If the function fails, the return value is zero.
//// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
//
//// Waits until the specified object is in the signaled state or the time-out interval elapses.
//typedef DWORD(WINAPI* WaitForSingleObject_t)(
//  IN HANDLE hHandle,							/*A handle to the object.*/
//  IN DWORD  dwMilliseconds						/*A handle to the object.*/
//);
//// If the function succeeds, the return value indicates the event that caused the function to return.
//// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
//
//// Writes data to an area of memory in a specified process.
//// The entire area to be written to must be accessible or the operation fails.
//typedef BOOL(WINAPI* WriteProcessMemory_t)(
//	IN		HANDLE  hProcess,					/*A handle to the process memory to be modified. The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.*/
//	IN		LPVOID  lpBaseAddress,				/*A pointer to the base address in the specified process to which data is written. Before data transfer occurs, the system verifies that all data in the base address and memory of the specified size is accessible for write access, and if it is not accessible, the function fails.*/
//	IN		LPCVOID lpBuffer,					/*A pointer to the buffer that contains data to be written in the address space of the specified process.*/
//	IN		SIZE_T  nSize,						/*The number of bytes to be written to the specified process.*/
//	OUT		SIZE_T* lpNumberOfBytesWritten		/*A pointer to a variable that receives the number of bytes transferred into the specified process. This parameter is optional. If lpNumberOfBytesWritten is NULL, the parameter is ignored.*/
//);
//// If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).
//// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory