#pragma once
#include <windows.h>

void deobfuscate_xor(unsigned char* data, SIZE_T data_len, unsigned char* key, SIZE_T key_len);