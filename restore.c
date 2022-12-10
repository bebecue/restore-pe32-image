#include <stdio.h>
#include <Windows.h>

#include "shared.h"

LPVOID read_file(const wchar_t *path) {
   HANDLE *handle = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    ENSURE(handle != INVALID_HANDLE_VALUE);

    DWORD size = GetFileSize(handle, NULL);
    ENSURE(size != INVALID_FILE_SIZE);

    LPVOID file_bytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

    DWORD number_of_bytes_read;
    ENSURE(ReadFile(handle, file_bytes, size, &number_of_bytes_read, NULL));
    ENSURE(number_of_bytes_read == size);
    ENSURE(CloseHandle(handle));

    return file_bytes;
}

void verify_memdump_nt_header(PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    ENSURE(memdump_nt_header_ptr->Signature == *(DWORD*)"PE\x00\x00");
    ENSURE(memdump_nt_header_ptr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
    ENSURE(memdump_nt_header_ptr->FileHeader.NumberOfSections != 0);
    ENSURE(memdump_nt_header_ptr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
}

DWORD calc_orig_image_size(PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    DWORD orig_image_size = 0;
    WORD section_index = 0;
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(memdump_nt_header_ptr);
    while (section_index < memdump_nt_header_ptr->FileHeader.NumberOfSections) {
        orig_image_size = max(orig_image_size, sh->PointerToRawData + sh->SizeOfRawData);

        section_index++;
        sh++;
    }
    return orig_image_size;
}

void copy_headers(LPBYTE orig_image_ptr, LPBYTE memdump_ptr, PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    CopyMemory(orig_image_ptr, memdump_ptr, memdump_nt_header_ptr->OptionalHeader.SizeOfHeaders);
}

void copy_sections(LPBYTE orig_image_ptr, LPBYTE memdump_ptr, PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(memdump_nt_header_ptr);
    WORD i = 0;
    while (i < memdump_nt_header_ptr->FileHeader.NumberOfSections) {
        CopyMemory(orig_image_ptr + sh->PointerToRawData, memdump_ptr + sh->VirtualAddress, sh->SizeOfRawData);

        i++;
        sh++;
    }
}

DWORD rva_to_file_offset(PIMAGE_NT_HEADERS32 memdump_nt_header_ptr, DWORD rva, DWORD size) {
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(memdump_nt_header_ptr);
    DWORD section_index = 0;
    while (section_index < memdump_nt_header_ptr->FileHeader.NumberOfSections)
    {
        if (sh->VirtualAddress <= rva && rva + size <= sh->VirtualAddress + sh->SizeOfRawData)
        {
            break;
        }

        sh++;
        section_index++;
    }
    ENSURE(section_index < memdump_nt_header_ptr->FileHeader.NumberOfSections);

    return sh->PointerToRawData + (rva - sh->VirtualAddress);
}

void reset_iat(LPBYTE orig_image_ptr, PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    if (IMAGE_DIRECTORY_ENTRY_IAT >= memdump_nt_header_ptr->OptionalHeader.NumberOfRvaAndSizes) return;

    PIMAGE_DATA_DIRECTORY iat_dir = &memdump_nt_header_ptr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat_dir->Size == 0) return;

    PIMAGE_DATA_DIRECTORY import_table_dir = &memdump_nt_header_ptr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    ENSURE(import_table_dir->VirtualAddress != 0);
    ENSURE(import_table_dir->Size != 0);

    DWORD import_table_dir_offset = rva_to_file_offset(memdump_nt_header_ptr, import_table_dir->VirtualAddress, import_table_dir->Size);
    DWORD iat_dir_offset = rva_to_file_offset(memdump_nt_header_ptr, iat_dir->VirtualAddress, iat_dir->Size);

    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(orig_image_ptr + import_table_dir_offset);
    while(1) {
        if (import_desc->OriginalFirstThunk == 0) {
            break;
        }

        PIMAGE_THUNK_DATA32 original_thunk_ptr = (PIMAGE_THUNK_DATA32)(
            orig_image_ptr + rva_to_file_offset(
                memdump_nt_header_ptr, import_desc->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA32))
            );

        PIMAGE_THUNK_DATA32 bound_thunk_ptr = (PIMAGE_THUNK_DATA32)(
            orig_image_ptr + rva_to_file_offset(
                memdump_nt_header_ptr, import_desc->FirstThunk, sizeof(IMAGE_THUNK_DATA32))
            );

        PIMAGE_THUNK_DATA32 p1 = original_thunk_ptr;
        PIMAGE_THUNK_DATA32 p2 = bound_thunk_ptr;
        while(1) {
            if (p1->u1.Function == 0) {
                ENSURE(p2->u1.Function == 0);
                break;
            } else {
                ENSURE(p2->u1.Function != 0);
                p1++;
                p2++;
            }
        }
        CopyMemory(bound_thunk_ptr, original_thunk_ptr, (p1 - original_thunk_ptr) * sizeof(IMAGE_THUNK_DATA32));

        import_desc++;
    }
}

void revert_relocation(
    LPBYTE orig_image_ptr,
    PIMAGE_DOS_HEADER dos_header,
    PIMAGE_NT_HEADERS32 memdump_nt_header_ptr)
{
    const DWORD ORIG_IMAGE_BASE = 0x400000;

    if (IMAGE_DIRECTORY_ENTRY_BASERELOC >= memdump_nt_header_ptr->OptionalHeader.NumberOfRvaAndSizes) return;

    PIMAGE_DATA_DIRECTORY base_reloc_dir = &memdump_nt_header_ptr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (base_reloc_dir->Size == 0) return;

    int delta = (int)ORIG_IMAGE_BASE - (int)memdump_nt_header_ptr->OptionalHeader.ImageBase;
    if (delta == 0) return;

    {
        // reset image base
        DWORD off = dos_header->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)
            + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, ImageBase);
        *(DWORD*)(orig_image_ptr + off) = ORIG_IMAGE_BASE;
    }

    DWORD dir_file_pointer = rva_to_file_offset(memdump_nt_header_ptr, base_reloc_dir->VirtualAddress, base_reloc_dir->Size);

    DWORD remaining_block_size = base_reloc_dir->Size;
    LPBYTE block_ptr = orig_image_ptr + dir_file_pointer;

    while (remaining_block_size > 0) {
        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)block_ptr;
        ENSURE(block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION));
        ENSURE(remaining_block_size >= block->SizeOfBlock);
        remaining_block_size -= block->SizeOfBlock;

        DWORD entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        LPWORD entry_ptr = (LPWORD)(block_ptr + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < entry_count; i++)
        {
            WORD entry = *entry_ptr++;

            DWORD rva = block->VirtualAddress + (entry & 0xfff);
            switch(entry >> 12) {
                case IMAGE_REL_BASED_ABSOLUTE: {
                    // padding
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW: {
                    DWORD rel_offset = rva_to_file_offset(memdump_nt_header_ptr, rva, sizeof(DWORD));
                    *(int*)(orig_image_ptr + rel_offset) += delta;
                    break;
                }
                default: {
                    printf("TODO: reloc type %#x\n", entry >> 12);
                    break;
                }
            }
        }

        block_ptr += block->SizeOfBlock;
    }
}

void sanity_check(LPBYTE orig_image_ptr, PIMAGE_NT_HEADERS32 memdump_nt_header_ptr) {
    DWORD entry_point_offset = rva_to_file_offset(memdump_nt_header_ptr, memdump_nt_header_ptr->OptionalHeader.AddressOfEntryPoint, 1);
    if (orig_image_ptr[entry_point_offset] != 0xe8) {
        printf("warn: call is not the first instruction\n");
    }
    if (orig_image_ptr[entry_point_offset + 5] != 0xe9) {
        printf("warn: jmp is not the second instruction\n");
    }
}

int wmain(int argc, const wchar_t *argv[])
{
    if (argc != 3) {
        wprintf(L"usage: %s <dump_path> <image_output_path>\n", argv[0]);
        return 1;
    }

    const wchar_t *dump_path = argv[1];
    const wchar_t *image_ouput_path = argv[2];

    LPBYTE memdump_ptr = read_file(dump_path);

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)memdump_ptr;
    PIMAGE_NT_HEADERS32 memdump_nt_header_ptr = (PIMAGE_NT_HEADERS32)(memdump_ptr + dos_header->e_lfanew);
    verify_memdump_nt_header(memdump_nt_header_ptr);

    DWORD orig_image_size = calc_orig_image_size(memdump_nt_header_ptr);
    ENSURE(orig_image_size != 0);

    LPBYTE orig_image = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, orig_image_size);

    copy_headers(orig_image, memdump_ptr, memdump_nt_header_ptr);

    copy_sections(orig_image, memdump_ptr, memdump_nt_header_ptr);

    reset_iat(orig_image, memdump_nt_header_ptr);

    revert_relocation(orig_image, dos_header, memdump_nt_header_ptr);

    sanity_check(orig_image, memdump_nt_header_ptr);

    write_file(image_ouput_path, orig_image, orig_image_size);

    return 0;
}
