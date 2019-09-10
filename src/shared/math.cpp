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
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "math.h"
#include "rc4.h"
#include "../config.h"

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

}

stl::string deterministic_uuid(uint64_t seed)
{
    char uuid[44];
    deterministic_uuid(seed, uuid);
    return uuid;
}
