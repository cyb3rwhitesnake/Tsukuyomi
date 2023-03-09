#include "..\HeaderFiles\FreshyCalls.h"

int custom_strncmp(const char* s1, const char* s2, unsigned int n) {
	for (unsigned int i = 0; i < n; i++) {
		if (s1[i] != s2[i]) {
			return -1;
		}
		else {
			if (s1[i] == '\0' || s2[i] == '\0') {
				return 0;
			}
		}
	}
	return 0;
}

void insertNode(node** head, long long function_address, int hash, int syscall_number) {
	HMODULE ntdll;
	ntdll = custom_GetModuleHandle(0x7d4a738d);

	RtlAllocateHeap_t pRtlAllocateHeap = (RtlAllocateHeap_t)custom_GetProcAddress(ntdll, 0xc0b381da);
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
	node* new_node = (node*)pRtlAllocateHeap(ProcEnvBlk->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(node));

	new_node->function_address = function_address;
	new_node->hash = hash;
	new_node->syscall_number = syscall_number;
	new_node->next_node = NULL;

	if ((*head == NULL) || ((*head)->function_address >= new_node->function_address)) {
		new_node->next_node = *head;
		*head = new_node;
		return;
	}

	node* current = *head;
	while (current->next_node != NULL && current->next_node->function_address < new_node->function_address) {
		current = current->next_node;
	}
	new_node->next_node = current->next_node;
	current->next_node = new_node;
}

void set_syscall_numbers(node* head) {
	node* current = head;
	int syscall_number = 0;
	while (current != NULL) {
		current->syscall_number = syscall_number;
		syscall_number++;
		current = current->next_node;
	}
}

int getSyscallbyHash(node* head, int hash) {
	node* current = head;
	while (current != NULL) {
		if (current->hash == hash) {
			return current->syscall_number;
		}
		current = current->next_node;
	}
	return -1;
}

unsigned long long int getAddressbyHash(node* head, int hash) {
	node* current = head;
	while (current != NULL) {
		if (current->hash == hash) {
			return current->function_address;
		}
		current = current->next_node;
	}
	return -1;
}

void createSyscallTable(node** head) {
	HMODULE ntdll;
	ntdll = custom_GetModuleHandle(0x7d4a738d);

	char* pBaseAddr = (char*)ntdll;

	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	void* pProcAddr = NULL;
	for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
		unsigned char* sTmpFuncName = (unsigned char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];
		if ((custom_strncmp((const char*)sTmpFuncName, "Nt", 2) == 0) && (custom_strncmp((const char*)sTmpFuncName, "Ntdll", 5) != 0)) {
			pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
			insertNode(head, (long long unsigned int)pProcAddr, djb2(sTmpFuncName), 0);
		}
	}

	set_syscall_numbers(*head);
}

ULONGLONG findSyscall(unsigned char* function_address) {
	while (TRUE) {
		if (function_address[0] == 0x0f) {
			if (function_address[1] == 0x05) {
				if (function_address[2] == 0xc3) {
					return (ULONGLONG)function_address;
				}
			}
		}
		function_address += 1;
	}
}