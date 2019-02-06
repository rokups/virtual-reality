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
//s
#pragma once


#include <windows.h>
#include <winhttp.h>
#include <stl/string.h>
#include <stl/unordered_map.h>

enum HttpRequestFlags
{
    NoRedirect = 1,
    KeepAlive = 2,
    NoValidateSSL = 4,
};

enum HttpStatus
{
    HttpOk = 200,
    HttpUnknownError = ~0U,
};

struct HttpRequest
{
    HttpRequest() = default;
    ~HttpRequest();

    HINTERNET internet{};
    stl::unordered_map<stl::string, stl::string> headers{};
    stl::string user_agent{"HttpClient"};
    stl::vector<unsigned char> content;
    unsigned resolve_timeout = 10000;
    unsigned connect_timeout = 30000;
    unsigned send_timeout = 30000;
    unsigned receive_timeout = 30000;
    unsigned flags = HttpUnknownError;

private:
    HttpRequest(const HttpRequest&) { };
};

struct HttpResponse
{
    unsigned status = ~0U;
    stl::unordered_map<stl::string, stl::string> headers;
    stl::string content;
};

HttpResponse send_http_request(HttpRequest& request, const stl::string& url, const stl::string& method = "GET");
