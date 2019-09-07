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
#pragma once

#include <windows.h>
#include <algorithm>
#include <stl/vector.h>
#include <stl/function.h>

typedef stl::function<void()> coro_func;

class coroutine_loop
{
    void* _main_fiber;
    unsigned int _sleep;
    bool _terminating;

    static unsigned CALLBACK _run_coro_func(void*);

    struct coro_ctx
    {
        void* this_fiber = nullptr;
        coro_func func{};
        unsigned sleep = 0;
        unsigned last_run = GetTickCount();
    };

public:
    coroutine_loop();
    static void activate(coroutine_loop& loop);
    void* get_main_fiber(unsigned int ms = 0);
    void start(const coro_func& coro, unsigned stack_size = 1024 * 32);
    void stop_all() { _terminating = true; }
    bool is_active() const { return !_terminating; }
    coro_ctx* get_current_coro() { return _current; }
    void run();

    static coroutine_loop* current_loop;

protected:
    stl::vector<coro_ctx*> _runnables;
    stl::vector<coro_ctx*> _starting;
    coro_ctx* _current = nullptr;
};

inline bool yield(unsigned sleepMs = 0) { SwitchToFiber(coroutine_loop::current_loop->get_main_fiber(sleepMs)); return coroutine_loop::current_loop->is_active(); }
#define coro_start(proc) coroutine_loop::current_loop->start(proc)
#define coro_run() coroutine_loop::current_loop->run();
