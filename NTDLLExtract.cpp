#include "..\HeaderFiles\NTDLLExtract.h"

void NTDLLExtractFromSuspended(node* head, const char* process_name, unsigned char** NTDLL_clean, unsigned int* NTDLL_size)
{
	ULONG_PTR pNtHeader;
	ULONG_PTR pFileHeader;
	ULONG_PTR pOptionalHeader;
	ULONG_PTR pCurrentSectionHeaders;

	PVOID source;
	PVOID destination;
	SIZE_T sizeToCopy;

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

	pNtHeader = (ULONG_PTR)ntdll + ((PIMAGE_DOS_HEADER)ntdll)->e_lfanew;
	pFileHeader = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)pNtHeader)->FileHeader;
	pOptionalHeader = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader;

	*NTDLL_size = ((PIMAGE_OPTIONAL_HEADER)pOptionalHeader)->SizeOfImage;

	SIZE_T memory_size = *NTDLL_size;
	RtlAllocateHeap_t pRtlAllocateHeap = (RtlAllocateHeap_t)custom_GetProcAddress(ntdll, 0xc0b381da);
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
	*NTDLL_clean = (unsigned char*)pRtlAllocateHeap(ProcEnvBlk->ProcessHeap, HEAP_ZERO_MEMORY, memory_size);

}