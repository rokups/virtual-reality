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
#include <utility>
#include "rc4.h"


void rc4_init(struct rc4_ctx* ctx, const unsigned char* key, int key_len)
{
    for (unsigned i = 0; i < 256; i++)
        ctx->s[i] = (unsigned char) i;

    unsigned j = 0;
    for (unsigned i = 0; i < 256; i++)
    {
        j = (j + ctx->s[i] + key[i % key_len]) % 256;
        std::swap(ctx->s[i], ctx->s[j]);
    }
}

void rc4_xor(struct rc4_ctx* ctx, unsigned char* buff, int len)
{
    unsigned x = 0, y = 0;
    for (unsigned i = 0; i < len; i++)
    {
        x = (x + 1) % 256;
        y = (y + ctx->s[x]) % 256;
        std::swap(ctx->s[x], ctx->s[y]);
        buff[i] ^= ctx->s[(ctx->s[x] + ctx->s[y]) % 256];
    }
}