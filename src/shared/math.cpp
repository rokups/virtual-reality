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
// Trick compiler into linking to _snprintf from ntdll and thus save executable size.
#define _NO_CRT_STDIO_INLINE
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "vr-config.h"
#include "math.h"
#include "rc4.h"

extern "C"
{

uint64_t deterministic_uuid_seed;

int random(int min, int max)
{
    auto range = max - min;
    assert(range > 0);
    float random = ((float)(rand() + rand())) / (RAND_MAX + RAND_MAX);
    return static_cast<int>(random * range + min);
}

uint64_t get_machine_hash()
{
    // Use unique per-machine GUID to seed generation of deterministic GUIDs to make them unique on each machine.
    uint64_t machine_hash = vr_shared_key;
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
                machine_hash ^= k;
        }
        RegCloseKey(hKey);
        hKey = nullptr;
    }

    return machine_hash;
}

void deterministic_uuid(uint64_t seed, char uuid[44])
{
    uint32_t a = 0;
    uint16_t b = 0;
    uint16_t c = 0;
    uint16_t d = 0;
    uint32_t e = 0;
    uint16_t f = 0;

    rc4_ctx rc4{};
    rc4_init(&rc4, deterministic_uuid_seed + seed);

    rc4_xor(&rc4, (uint8_t*)&a, sizeof(a));
    rc4_xor(&rc4, (uint8_t*)&b, sizeof(b));
    rc4_xor(&rc4, (uint8_t*)&c, sizeof(c));
    rc4_xor(&rc4, (uint8_t*)&d, sizeof(d));
    rc4_xor(&rc4, (uint8_t*)&e, sizeof(e));
    rc4_xor(&rc4, (uint8_t*)&f, sizeof(f));

    c &= 0xfff; // Clear first digit so it can be always 4. Lets pretend its uuid4.

    _snprintf(uuid, 44, "{%08X-%04X-4%03X-%04X-%08X-%04X}", a, b, c, d, e, f);
}

HANDLE mutex_create(uint64_t seed)
{
    char mutexName[51] = "Global\\";
    deterministic_uuid(seed, mutexName + 7);
    return CreateMutexA(NULL, FALSE, mutexName);
}

bool mutex_acquire(HANDLE mutex)
{
    if (mutex == NULL)
        return false;
    auto result = WaitForSingleObject(mutex, 0);
    return result == WAIT_ABANDONED || result == WAIT_OBJECT_0;
}

HANDLE mutex_lock(uint64_t seed)
{
    if (HANDLE mutex = mutex_create(seed))
    {
        if (mutex_acquire(mutex))
            return mutex;
        CloseHandle(mutex);
    }
    return 0;
}

BOOL mutex_is_locked(uint64_t seed)
{
    if (HANDLE mutex = mutex_lock(seed))
    {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return FALSE;
    }
    return TRUE;
}

int64_t combine_hash(int64_t result, int64_t hash)
{
    return result ^ (hash + 0x9ddfea08eb382d69 + (result << 12) + (result >> 4));
}

uint32_t fnv32a(const void* data, int len)
{
    uint32_t hash = 2166136261;
    for (const uint8_t* p = (const uint8_t*)data, * end = p + len; p < end; p++)
    {
        hash ^= *p;
        hash *= 16777619;
    }
    return hash;
}

}

stl::string deterministic_uuid(uint64_t seed)
{
    char uuid[44];
    deterministic_uuid(seed, uuid);
    return uuid;
}
