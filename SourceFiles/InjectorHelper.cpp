#include "..\HeaderFiles\InjectorHelper.h"

int custom_strcmp(unsigned char* x, unsigned char* y) {
	while (*x != 0x00 && *y != 0x00) {
		if (*x != *y) {
			return -1;
		}
		x++;
		y++;
	}
	return 0;
}

int FindTarget(const char* procName) {
	HMODULE kernel32;
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32;
	int pid = 0;

	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)custom_GetProcAddress(kernel32, 0x66851295);
	hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	Process32Next_t pProcess32Next = (Process32Next_t)custom_GetProcAddress(kernel32, 0x90177f28);
	while (pProcess32Next(hSnapshot, &pe32)) {
		if (custom_strcmp((unsigned char*)procName, (unsigned char*)pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle_t pCloseHandle = (CloseHandle_t)custom_GetProcAddress(kernel32, 0x3870ca07);
	pCloseHandle(hSnapshot);

	return pid;
}

void FindThread(int pid, PHANDLE threadsArray, unsigned int* n_threads) {
	HMODULE kernel32;
	HANDLE hSnapshot;
	THREADENTRY32 te32;

	kernel32 = custom_GetModuleHandle(0x294e3ff5);

	CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)custom_GetProcAddress(kernel32, 0x66851295);
	hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	te32.dwSize = sizeof(te32);
	Thread32Next_t pThread32Next = (Thread32Next_t)custom_GetProcAddress(kernel32, 0x695209e1);
	while (pThread32Next(hSnapshot, &te32)) {
		if (te32.th32OwnerProcessID == pid) {
			OpenThread_t pOpenThread = (OpenThread_t)custom_GetProcAddress(kernel32, 0x806cb78f);
			threadsArray[*n_threads] = pOpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			(*n_threads)++;
		}
	}
	CloseHandle_t pCloseHandle = (CloseHandle_t)custom_GetProcAddress(kernel32, 0x3870ca07);
	pCloseHandle(hSnapshot);
}