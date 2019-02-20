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
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "math.h"
#include "rc4.h"

int random(int min, int max)
{
    auto range = max - min;
    assert(range > 0);
    float random = ((float)(rand() + rand())) / (RAND_MAX + RAND_MAX);
    return static_cast<int>(random * range + min);
}

uint64_t deterministic_uuid_seed = 0;

stl::string deterministic_uuid(uint64_t seed)
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

    stl::string result;
    result.resize(43);
    snprintf(&result.at(0), result.size(), "{%08X-%04X-4%03X-%04X-%08X-%04X}", a, b, c, d, e, f);

    return result;
}
