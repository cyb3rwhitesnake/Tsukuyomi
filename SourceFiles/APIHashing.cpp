#include "..\HeaderFiles\APIHashing.h"

// Return the hash of an ASCII string
unsigned int djb2(unsigned char* string) {
	unsigned int hash = 5381;
	int c;
	while (c = *string++) {
		hash = (((hash << 5) + hash) + c) & 0xffffffff;
	}
	return hash;
}

// Return the hash of an UNICODE string
unsigned int djb2W(unsigned char* string) {
	unsigned int hash = 5381;
	int c;
	do {
		c = *string;
		hash = (((hash << 5) + hash) + c) & 0xffffffff;
		string += 2;
	} while (c != 0);
	return hash;
}

// Custom implementation of GetModuleHandle
HMODULE WINAPI custom_GetModuleHandle(unsigned int hash) {
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);

	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;
	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
		if (hash == djb2W((unsigned char*)pEntry->BaseDllName.Buffer)) {
			return (HMODULE)pEntry->DllBase;
		}
	}
	return NULL;
}

// Custom implementation of GetProcAddress
// NOTE: It only works for direct exports by name
FARPROC WINAPI custom_GetProcAddress(HMODULE hMod, unsigned int hash) {
	char* pBaseAddr = (char*)hMod;

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
		if (hash == djb2(sTmpFuncName)) {
			pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
			break;
		}
	}

	return (FARPROC)pProcAddr;
}