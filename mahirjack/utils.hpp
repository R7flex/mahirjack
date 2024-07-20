#pragma once
#include "definitions.hpp"

#define printf(text, ...) (DbgPrintEx(0, 0, text, ##__VA_ARGS__))

namespace utils
{
    void* get_system_information(SYSTEM_INFORMATION_CLASS information_class)
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation(information_class, buffer, size, &size);

        void* info = ExAllocatePoolWithTag((POOL_TYPE)(NonPagedPool | POOL_ZERO_ALLOCATION), size, 'r7f0');
        if (!info)
            return nullptr;

        if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
            ExFreePool(info);
            return nullptr;
        }

        return info;
    }

    uintptr_t get_kernel_module(const char* name)
    {
        const auto to_lower = [](char* string) -> const char* {
            for (char* pointer = string; *pointer != '\0'; ++pointer) {
                *pointer = (char)(short)tolower(*pointer);
            }

            return string;
        };

        const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);

        if (!info)
            return NULL;

        for (size_t i = 0; i < info->NumberOfModules; ++i) {
            const auto& mod = info->Modules[i];

            if (strcmp(to_lower((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0) {
                const void* address = mod.ImageBase;
                ExFreePoolWithTag(info, 0);
                return (uintptr_t)address;
            }
        }

        ExFreePoolWithTag(info, 0);
        return NULL;
    }

    uintptr_t pattern_scan(uintptr_t base, size_t range, const char* pattern, const char* mask)
    {
        const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool {
            for (; *mask; ++base, ++pattern, ++mask) {
                if (*mask == 'x' && *base != *pattern)
                    return false;
            }

            return true;
        };

        range = range - strlen(mask);

        for (size_t i = 0; i < range; ++i) {
            if (check_mask((const char*)base + i, pattern, mask))
                return base + i;
        }

        return NULL;
    }

    uintptr_t pattern_scan(uintptr_t base, const char* pattern, const char* mask)
    {
        const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++) {
            const PIMAGE_SECTION_HEADER section = &sections[i];

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                const uintptr_t match = pattern_scan(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (match)
                    return match;
            }
        }

        return 0;
    }

    bool my_write(void* address, void* buffer, const size_t size)
    {
        auto* mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, nullptr);
        if (!mdl)
            return false;
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        auto* const mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
        MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        memcpy(mapping, buffer, size);
        MmUnmapLockedPages(mapping, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return true;
    }
}