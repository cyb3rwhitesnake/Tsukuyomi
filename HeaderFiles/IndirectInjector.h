#pragma once
#include <windows.h>
#include "FreshyCalls.h"
#include "InjectorHelper.h"
#include "..\Customization.h"

void ThreadInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len);
void ContextInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len);
void MapViewInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len);
void APCLazyInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len);
void APCEagerInjection(node* head, const char* process_name, unsigned char* payload, SIZE_T payload_len);