#include "syscall_stub.h"

void* rf(const char* filepath, DWORD* filesize) {
    HANDLE file1 = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file1 == INVALID_HANDLE_VALUE) return NULL;

    *filesize = GetFileSize(file1, NULL);
    if (*filesize == INVALID_FILE_SIZE) return NULL;

    void* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *filesize);
    if (!buffer || !ReadFile(file1, buffer, *filesize, NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(file1);
        return NULL;
    }

    CloseHandle(file1);
    return buffer;
}

DWORD rva_to_offset(PIMAGE_NT_HEADERS ntheaders, DWORD rva) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntheaders);
    for (int i = 0; i < ntheaders->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return rva - section->VirtualAddress + section->PointerToRawData;
        }
    }
    return 0;
}

void* get_proc_address(void* ntdllbuffer, const char* functionname) {
    DWORD_PTR base_addr = (DWORD_PTR)ntdllbuffer;
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)(base_addr + dos_hdr->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)(base_addr + rva_to_offset(nt_hdrs, nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

    PDWORD name_table = (PDWORD)(base_addr + rva_to_offset(nt_hdrs, exp_dir->AddressOfNames));
    PWORD ord_table = (PWORD)(base_addr + rva_to_offset(nt_hdrs, exp_dir->AddressOfNameOrdinals));
    PDWORD func_table = (PDWORD)(base_addr + rva_to_offset(nt_hdrs, exp_dir->AddressOfFunctions));

    for (DWORD i = 0; i < exp_dir->NumberOfNames; i++) {
        if (_stricmp((char*)(base_addr + rva_to_offset(nt_hdrs, name_table[i])), functionname) == 0) {
            return (void*)(base_addr + rva_to_offset(nt_hdrs, func_table[ord_table[i]]));
        }
    }
    return NULL;
}

BOOL get_syscall_stub(const char* functionname, void* syscall_stub) {
    DWORD filesize;
    void* ntdllbuffer = rf("C:\\Windows\\System32\\ntdll.dll", &filesize);
    if (!ntdllbuffer) return FALSE;

    void* function_addr = get_proc_address(ntdllbuffer, functionname);
    if (!function_addr) {
        HeapFree(GetProcessHeap(), 0, ntdllbuffer);
        return FALSE;
    }

    memcpy(syscall_stub, function_addr, sysstubsize);
    HeapFree(GetProcessHeap(), 0, ntdllbuffer);
    return TRUE;
}

int exec() {
    void* ntalloc_vm_stub = VirtualAlloc(NULL, sysstubsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ntalloc_vm_stub || !get_syscall_stub("NtAllocateVirtualMemory", ntalloc_vm_stub)) {
        printf("[-] Failed to fetch syscall stub for NtAllocateVirtualMemory.\n");
        return 1;
    }

    typedef NTSTATUS(WINAPI* ntallocatevirtualmemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    ntallocatevirtualmemory_t ntallocatevirtualmemory = (ntallocatevirtualmemory_t)ntalloc_vm_stub;

    void* scbuff = NULL;
    SIZE_T scsize = 512;
    NTSTATUS stt = ntallocatevirtualmemory(GetCurrentProcess(), &scbuff, 0, &scsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    printf("[+] Shellcode memory allocated at: 0x%p, Status: 0x%x\n", scbuff, stt);
    
    VirtualFree(ntalloc_vm_stub, 0, MEM_RELEASE);
    return 0;
}
