#ifndef SYSCALL_STUB_H
#define SYSCALL_STUB_H

#include <windows.h>
#include <stdio.h>

#define sysstubsize 23

void* rf(const char* filepath, DWORD* filesize);
DWORD rva_to_offset(PIMAGE_NT_HEADERS ntheaders, DWORD rva);
void* get_proc_address(void* ntdllbuffer, const char* functionname);
BOOL get_syscall_stub(const char* functionname, void* syscall_stub);
int exec();

#endif
