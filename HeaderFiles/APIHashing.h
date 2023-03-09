#pragma once
#include <windows.h>
#include "UndocumentedStruct.h"

unsigned int djb2(unsigned char* string);
unsigned int djb2W(unsigned char* string);
HMODULE WINAPI custom_GetModuleHandle(unsigned int hash);
FARPROC WINAPI custom_GetProcAddress(HMODULE hMod, unsigned int hash);