#define ENSURE(expr) if(!(expr)) { \
                         printf("bailed at line %d, last error = %d\n", __LINE__, GetLastError()); \
                         exit(127); \
                     }

void write_file(const wchar_t *path, void* bytes, DWORD size) {
    HANDLE *handle = CreateFileW(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    ENSURE(handle != INVALID_HANDLE_VALUE);

    DWORD number_of_bytes_written;
    ENSURE(WriteFile(handle, bytes, size, &number_of_bytes_written, NULL));
    ENSURE(number_of_bytes_written == size);
    ENSURE(CloseHandle(handle));
}
