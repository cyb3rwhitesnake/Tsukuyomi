#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include "DocumentedFunctions.h"
#include "APIHashing.h"

int FindTarget(const char* procName);
void FindThread(int pid, PHANDLE threadsArray, unsigned int* n_threads);