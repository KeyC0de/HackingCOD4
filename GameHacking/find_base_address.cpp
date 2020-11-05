#include "process_work.h"

DWORD GetProcessBaseAddress()
{
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (Module32First(hSnapshot, &me32))
	{
		CloseHandle(hSnapshot);
		return (DWORD)me32.modBaseAddr;
	}

	CloseHandle(hSnapshot);
	return 0;
}


#define PSAPI_VERSION 1

#include <psapi.h>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
#pragma comment(lib, "psapi.lib")

void GetBaseAddressByName(DWORD processId, TCHAR *processName)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processId);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
			&cbNeeded, LIST_MODULES_32BIT | LIST_MODULES_64BIT))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
			if (!_stricmp(processName, szProcessName)) {
				std::cout << (TEXT("0x%p\n"), hMod);
			}
		}
	}

	CloseHandle(hProcess);
}

int main(void)
{
	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;

	// Get the list of process identifiers.
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return 1;

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Check the names of all the processess (Case insensitive)
	for (int i = 0; i < cProcesses; i++) {
		GetBaseAddressByName(aProcesses[i], TEXT("SpiderSolitaire.exe"));
	}

	return 0;
}
