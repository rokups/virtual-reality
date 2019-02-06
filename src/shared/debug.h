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

enum class DebugLevel
{
    Debug,
    Warning,
    Error,
    Critical,
};

#define DEBUG_MIN_LOG_LEVEL DebugLevel::Debug

void debug_log(const char* format, DebugLevel lvl, const char* file, unsigned line, ...);
void debug_log(const wchar_t* format, DebugLevel lvl, const char* file, unsigned line, ...);

#if _DEBUG
#	define LOG_CRITICAL(format, ...)	debug_log(format, DebugLevel::Critical, __FILE__, __LINE__, ##__VA_ARGS__)
#	define LOG_ERROR(format, ...)		debug_log(format, DebugLevel::Error, __FILE__, __LINE__, ##__VA_ARGS__)
#	define LOG_WARNING(format, ...)		debug_log(format, DebugLevel::Warning, __FILE__, __LINE__, ##__VA_ARGS__)
#	define LOG_DEBUG(format, ...)		debug_log(format, DebugLevel::Debug, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#	define LOG_CRITICAL(...)	(void)0
#	define LOG_ERROR(...)		(void)0
#	define LOG_WARNING(...)		(void)0
#	define LOG_DEBUG(...)		(void)0
#endif
