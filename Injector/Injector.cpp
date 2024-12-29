// injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

int find_pid(const char* procname);
void injectToProcess(int pid, const char* injectedDLLName);


int main(int argc, char** argv)
{
	int pid;
	const char* procname = "explorer.exe";
	const char* injectDLLName = "C:\\Users\\Daniel\\Documents\\University\\Advanced topics in malware\\DllPatcher\\Injector\\x64\\Debug\\APIHooking.dll";
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

void injectToProcess(int pid, const char* injectedDLLName) {
	HMODULE kernelDLL = GetModuleHandle("Kernel32.dll");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, strlen(injectedDLLName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpAddress == NULL) {
		std::cout << "Failed to allocate memory in process" << std::endl;
		return;
	}
	SIZE_T written;
	WriteProcessMemory(hProcess, lpAddress, (LPVOID)injectedDLLName, strlen(injectedDLLName) + 1, &written);
	if (written != strlen(injectedDLLName) + 1) {
		std::cout << "Failed to write to process memory" << std::endl;
		return;
	}
	LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(kernelDLL, "LoadLibraryA");
	DWORD threadID;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibrary, lpAddress, 0, (LPDWORD)&threadID);
	if (hThread == NULL) {
		std::cout << "Failed to create remote thread" << std::endl;
		return;
	}
	std::cout << "Injected successfully" << std::endl;
	std::cout << "Thread ID: " << threadID << std::endl;
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);
}
