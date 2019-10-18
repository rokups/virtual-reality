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
#include <stl/string.h>
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

    stl::string base_msg = stl::string::format(format, ap);
    stl::string msg = stl::string::format("[%02d:%02d:%02d] %s", ts->tm_hour, ts->tm_min, ts->tm_sec, base_msg.c_str());
    if (IsDebuggerPresent())
    {
        msg += "\n";
        printf("%s", msg.c_str());
    }
    else
        printf("%s\n", msg.c_str());
    OutputDebugStringA(msg.c_str());
    va_end(ap);
}
#endif
