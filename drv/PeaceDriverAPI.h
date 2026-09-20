#pragma once

#include <cstdint>
#include <Windows.h>

// check if the system is virtualized
bool is_hv_running();

// read from arbitrary physical memory
size_t read_phys_mem(void* dst, uint64_t src, size_t size);

// write to arbitrary physical memory
size_t write_phys_mem(uint64_t dst, void const* src, size_t size);

// read from virtual memory in another process
size_t read_virt_mem(uint64_t cr3, void* dst, void const* src, size_t size);

// write to virtual memory in another process
size_t write_virt_mem(uint64_t cr3, void* dst, void const* src, size_t size);

// get the kernel CR3 value of an arbitrary process
uint64_t query_process_cr3(uint64_t pid);

// install an EPT hook for the CURRENT logical processor ONLY
bool install_ept_hook(uint64_t orig_page_pfn, uint64_t exec_page_pfn);

// remove a previously installed EPT hook
void remove_ept_hook(uint64_t orig_page_pfn);

// translate a virtual address to its physical address
uint64_t get_physical_address(uint64_t cr3, void const* address);

// hide a physical page from the guest
bool hide_physical_page(uint64_t pfn);

// unhide a physical page from the guest
void unhide_physical_page(uint64_t pfn);

// get the base address of the hypervisor
void* get_hv_base();

// write to the logger whenever a certain physical memory range is accessed
void* install_mmr(uint64_t address, uint32_t size, uint8_t mode);

// remove an existing MMR
void remove_mmr(void* handle);

// remove every installed MMR
void remove_all_mmrs();

void virtualhard();

// VT功能结束

// REG功能开始
void pingREG();

void virtualhardware();

bool readMemory(ULONG64 processId, ULONG64 address, ULONG64 size, void* buffer);

bool writeMemory(ULONG64 processId, ULONG64 address, ULONG64 size, void* buffer);

ULONG64 allocMemory(ULONG64 processId, ULONG64 size);

bool freeMemory(ULONG64 processId, ULONG64 address);

bool queryMemory(ULONG64 processId, ULONG64 address, ULONG& meminfo);

DWORD getPid(const wchar_t* processName);

ULONG64 getModuleBase(DWORD pid, const wchar_t* moduleName);

bool protectPid(ULONG64 processId);

bool unprotectPid();

bool remoteThread(ULONG64 processId, ULONG64 address);

bool injectionDll(ULONG64 processId, const wchar_t* dllPath);

bool apcInject(ULONG64 processId, const void* dllBuffer, ULONG64 dllSize);

bool fakeProcess(ULONG64 targetProcessId, ULONG64 templateProcessId);

bool restoreFakeProcess();

bool virtualHard(bool enable);

bool protectWindow(DWORD processId, HWND hWnd);

bool unprotectWindow(DWORD processId, HWND hWnd);

bool antiSnapshot(HWND hWnd);

bool antiSnapshot(HWND hWnd, bool enable);

// REG功能结束

// 键鼠封装开始


// 键鼠封装结束
