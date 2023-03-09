#pragma once
#include <windows.h>
#include "APIHashing.h"
#include "UndocumentedFunctions.h"

typedef struct node_t {
	long long unsigned int function_address;
	int hash;
	int syscall_number;
	node_t* next_node;
} node;

void createSyscallTable(node** head);
int getSyscallbyHash(node* head, int hash);
unsigned long long int getAddressbyHash(node* head, int hash);
ULONGLONG findSyscall(unsigned char* function_address);