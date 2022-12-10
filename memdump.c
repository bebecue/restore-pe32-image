#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <psapi.h>

#include "shared.h"

int wmain(int argc, const wchar_t *argv[])
{
    if (argc != 3) {
        wprintf(L"usage: %s <pid> <output>\n", argv[0]);
        return 1;
    }

    unsigned long pid = wcstoul(argv[1], NULL, 0);
    printf("PID: %lu\n", pid);
    ENSURE(pid != 0);

    const wchar_t *output_filepath = argv[2];

    HANDLE process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    ENSURE(process_handle);

    HMODULE exe_module_handle = NULL;
    size_t lpcbNeeded = 0;
    // retrieve only the first module that belongs to .exe file
    ENSURE(EnumProcessModules(process_handle, &exe_module_handle, sizeof(HMODULE), &lpcbNeeded));

    wchar_t exe_path[MAX_PATH] = { 0 };
    ENSURE(GetModuleFileNameExW(process_handle, exe_module_handle, exe_path, sizeof(exe_path) / sizeof(wchar_t)));
    wprintf(L"exe @ %s\n", exe_path);

    MODULEINFO exe_module_info = { 0 };
    ENSURE(GetModuleInformation(process_handle, exe_module_handle, &exe_module_info, sizeof(MODULEINFO)));
    printf("load address: 0x%p\n", exe_module_info.lpBaseOfDll);

    void *memdump_bytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, exe_module_info.SizeOfImage);
    size_t number_of_bytes_read = 0;
    ENSURE(
        ReadProcessMemory(
            process_handle,
            exe_module_info.lpBaseOfDll,
            memdump_bytes,
            exe_module_info.SizeOfImage,
            &number_of_bytes_read
        )
    );
    ENSURE(number_of_bytes_read == exe_module_info.SizeOfImage);
    write_file(output_filepath, memdump_bytes, exe_module_info.SizeOfImage);

    return 0;
}
