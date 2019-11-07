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
#include "coroutine.h"
#include "../shared/debug.h"

coroutine_loop* coroutine_loop::current_loop{};

unsigned coroutine_loop::_run_coro_func(void*)
{
    auto* loop = current_loop;
    {
        coro_ctx context{};
        context.this_fiber = GetCurrentFiber();
        loop->_starting.push_back(&context);

        if (loop->_current)
            SwitchToFiber(loop->_current->this_fiber);
        else
            SwitchToFiber(loop->get_main_fiber());

        loop->get_current_coro()->func();
        context.sleep = ~0U;    // exit hint
    }
    SwitchToFiber(loop->get_main_fiber());
    return 0;
}

coroutine_loop::coroutine_loop()
{
    _sleep = 0;
    _terminating = false;
}

void coroutine_loop::activate(coroutine_loop& loop)
{
    current_loop = &loop;
    if (loop._main_fiber == nullptr)
        loop._main_fiber = ConvertThreadToFiber(nullptr);
}

void* coroutine_loop::get_main_fiber(unsigned int ms)
{
    _sleep = ms;
    return _main_fiber;
}

void coroutine_loop::start(const coro_func& coro, unsigned stack_size)
{
    void* fiber = CreateFiber(stack_size, (LPFIBER_START_ROUTINE)&_run_coro_func, nullptr);
    SwitchToFiber(fiber);
    _starting.back()->func = coro;
}

void coroutine_loop::run()
{
    while (!_runnables.empty() || !_starting.empty())
    {
        _runnables.insert(_runnables.end(), _starting.begin(), _starting.end());
        _starting.clear();

        // Sort runnables by next run time. Runners to front, sleepers to back.
        // std::sort(_runnables.begin(), _runnables.end(), [](coro_ctx* a, coro_ctx* b) {
        //     unsigned a_slept = GetTickCount() - a->last_run;
        //     unsigned b_slept = GetTickCount() - b->last_run;
        //     return (a->sleep - a_slept) < (b->sleep - b_slept);
        // });

        int sleep_time = INT_MAX;
        for (auto it = _runnables.begin(); it != _runnables.end();)
        {
            auto& runnable = *it;
            unsigned time_slept = GetTickCount() - runnable->last_run;
            int time_left_to_sleep = runnable->sleep - time_slept;
            if (_terminating || time_left_to_sleep <= 0)
            {
                _current = runnable;
                SwitchToFiber(runnable->this_fiber);

                if(_sleep == ~0U)
                {
                    DeleteFiber(runnable->this_fiber);
                    it = _runnables.erase(it);
                }
                else
                {
                    runnable->last_run = GetTickCount();
                    runnable->sleep = _sleep;

                    _current = nullptr;
                    _sleep = 0;

                    sleep_time = min(sleep_time, (int) runnable->sleep);

                    ++it;
                }
            }
            else
            {
                sleep_time = min(sleep_time, time_left_to_sleep);
                ++it;
            }
        }
        Sleep((unsigned)sleep_time);
    }
}
