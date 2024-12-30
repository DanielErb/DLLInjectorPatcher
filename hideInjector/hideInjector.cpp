// injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>

int find_pid(const char* procname);
void injectToProcess(int pid, const char* injectedDLLName);
HMODULE getRemoteDLLModuleHandle(HANDLE hProcess, char* injectDLLName);


int main(int argc, char** argv)
{
	int pid;
	const char* procname = "Taskmgr.exe";
	const char* injectDLLName = "APIHooking.dll";
	if (argc == 2) {
		pid = atoi(argv[1]);
	}
	else {
		pid = find_pid(procname);
		if (pid == 0) {
			std::cout << "Process not found" << std::endl;
			return 1;
		}
	}
	std::cout << "Process pid is: " << pid << std::endl;
	injectToProcess(pid, injectDLLName);
}


int find_pid(const char* procname) {
	PROCESSENTRY32 entry;
	entry.dwFlags = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (strcmp(entry.szExeFile, procname) == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}

HMODULE getRemoteDLLModuleHandle(HANDLE hProcess, char* injectDLLName) {
	HMODULE hModules[1024];
	DWORD lpcbNeeded;
	if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &lpcbNeeded)) {
		for (int i = 0; i < lpcbNeeded / sizeof(HMODULE); i++) {
			char szModName[MAX_PATH];
			if (GetModuleBaseNameA(hProcess, hModules[i], szModName, sizeof(szModName))) {
				if (strcmp(szModName, injectDLLName) == 0) {
					return hModules[i];
				}
			}

		}
	}
	return NULL;

}

void injectToProcess(int pid, const char* injectedDLLName) {
	HMODULE kernelDLL = GetModuleHandle("Kernel32.dll");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(kernelDLL, "FreeLibrary");
	HMODULE hModule = getRemoteDLLModuleHandle(hProcess, (char*)injectedDLLName);
	DWORD threadID;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibrary, hModule, 0, (LPDWORD)&threadID);
	if (hThread == NULL) {
		std::cout << "Failed to create remote thread" << std::endl;
		return;
	}
	std::cout << "Removed successfully" << std::endl;
	std::cout << "Thread ID: " << threadID << std::endl;
	CloseHandle(hThread);
	CloseHandle(hProcess);
}
