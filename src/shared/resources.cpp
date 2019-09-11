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
#include <string.h>
#include "miniz.h"
#include "rc4.h"
#include "resources.h"

bool resource_open(stl::vector<uint8_t>& output, const uint8_t* data, unsigned dlen, const uint8_t* key, unsigned klen)
{
    if (output.size() < dlen)
        return false;

    stl::vector<uint8_t> decrypted{};
    decrypted.resize(dlen);
    memcpy(decrypted.data(), data, dlen);

    rc4_ctx rc4{};
    rc4_init(&rc4, key, klen);
    rc4_xor(&rc4, decrypted.data(), dlen);

    mz_ulong size = (mz_ulong)output.size();
    if (mz_uncompress(output.data(), &size, decrypted.data(), (mz_ulong)decrypted.size()) != MZ_OK)
        return false;

    return size == output.size();
}
