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
#include "win32.h"


stl::string GetFolderPath(unsigned id)
{
    char path[MAX_PATH]{};
    SHGetFolderPathA(nullptr, id, nullptr, SHGFP_TYPE_DEFAULT, path);
    return path;
}

stl::vector<wchar_t> to_wstring(const stl::string& str)
{
    stl::vector<wchar_t> result;
    if (auto need = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0))
    {
        result.resize(static_cast<size_t>(need) + 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(),
            static_cast<int>(str.size()), result.data(), static_cast<int>(result.size()));
    }
    return result;
}

stl::string from_wstring(const wchar_t* str)
{
    stl::string result;
    int len = static_cast<int>(wcslen(str));
    if (auto need = WideCharToMultiByte(CP_UTF8, 0, str, len, nullptr, 0, nullptr, nullptr))
    {
        result.resize(static_cast<size_t>(need) + 1);
        WideCharToMultiByte(CP_UTF8, 0, str, len, &result.at(0), static_cast<int>(result.size()), nullptr, nullptr);
    }
    return result;
}
