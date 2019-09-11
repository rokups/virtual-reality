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
#include <stl/vector.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include "debug.h"

#ifdef DEBUG_MIN_LOG_LEVEL
extern "C" void debug_log(DebugLevel lvl, const char* format, const char* file, unsigned line, ...)
{
    if (DEBUG_MIN_LOG_LEVEL > lvl)
        return;

    va_list ap;
    va_start(ap, line);

    time_t now = 0;
    time(&now);
    tm* ts = localtime(&now);
    stl::vector<char> timestamp(20);
    auto need = static_cast<size_t>(_snprintf(timestamp.data(), timestamp.size(), "[%02d:%02d:%02d]", ts->tm_hour, ts->tm_min, ts->tm_sec));
    auto timestamp_len = strlen(timestamp.data());
    assert(need < timestamp.size());

    stl::vector<char> msg(timestamp.size() + strlen(format) * 2, 0);

    need = vsnprintf(msg.data(), msg.size(), format, ap) + timestamp_len + 1;
    if (msg.size() <= need)
    {
        msg.resize(need + 1);
        vsnprintf(msg.data(), msg.size(), format, ap);
    }

    memmove(msg.data() + timestamp_len + 1, msg.data(), strlen(msg.data()));
    memmove(msg.data(), timestamp.data(), timestamp_len);
    msg.data()[timestamp_len] = ' ';

    OutputDebugStringA(msg.data());
    printf("%s\n", msg.data());

    va_end(ap);
}
#endif
