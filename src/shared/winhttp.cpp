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
#include <winhttp.h>
#include <cassert>
#include <miniz.h>
#include <mini_gzip.h>
#include <stl/vector.h>
#include "winhttp.h"


static stl::vector<wchar_t> to_wstring(const stl::string& str)
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

static stl::string from_wstring(const wchar_t* str)
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

HttpRequest::~HttpRequest()
{
    if (internet)
        WinHttpCloseHandle(internet);
}

HttpResponse send_http_request(HttpRequest& request, const stl::string& url, const stl::string& method)
{
    HttpResponse response{};
    stl::vector<wchar_t> verb = to_wstring(method.to_upper());

    if (request.internet == nullptr)
    {
        request.internet = WinHttpOpen(to_wstring(request.user_agent).data(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

        if (request.internet == nullptr)
            return {};

        WinHttpSetTimeouts(request.internet, request.resolve_timeout, request.connect_timeout, request.send_timeout,
            request.receive_timeout);
    }

    stl::vector<wchar_t> wHostName(MAX_PATH, 0);
    stl::vector<wchar_t> wUrlPath(MAX_PATH * 5, 0);
    URL_COMPONENTS urlParts{};
    urlParts.dwStructSize = sizeof(urlParts);
    urlParts.lpszHostName = wHostName.data();
    urlParts.dwHostNameLength = static_cast<DWORD>(wHostName.size());
    urlParts.lpszUrlPath = wUrlPath.data();
    urlParts.dwUrlPathLength = static_cast<DWORD>(wUrlPath.size());
    urlParts.dwSchemeLength = 1; // None zero

    auto wUrl = to_wstring(url);
    if (!WinHttpCrackUrl(wUrl.data(), (DWORD) wUrl.size(), 0, &urlParts))
        return {};

    HINTERNET hConnect = WinHttpConnect(request.internet, wHostName.data(), urlParts.nPort, 0);
    if (!hConnect)
        return {};

    struct AutoCloseWinHttpHandle
    {
        HINTERNET handle;
        ~AutoCloseWinHttpHandle()
        {
            WinHttpCloseHandle(handle);
        }
    } autoCloseHConnect{hConnect};

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb.data(), urlParts.lpszUrlPath, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, (urlParts.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);

    if (!hRequest)
        return {};

    AutoCloseWinHttpHandle autoCloseHRequest{hRequest};

    // If HTTPS, then client is very susceptable to invalid certificates
    // Easiest to accept anything for now
    if (urlParts.nScheme == INTERNET_SCHEME_HTTPS && !(request.flags & NoValidateSSL))
    {
        DWORD option = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&option, sizeof(DWORD));
    }

    // keep-alive
    {
        DWORD option = WINHTTP_DISABLE_KEEP_ALIVE;
        WinHttpSetOption(hRequest, (request.flags & KeepAlive) ?
        WINHTTP_OPTION_ENABLE_FEATURE : WINHTTP_OPTION_DISABLE_FEATURE, (LPVOID)&option, sizeof(option));
    }

    if (!request.headers.empty())
    {
        stl::string all_headers;
        for (auto& header : request.headers)
        {
            all_headers += header.first;
            all_headers += ": ";
            all_headers += header.second;
            all_headers += "\r\n";
        }
        assert(all_headers.size() > 2);
        all_headers = all_headers.substring(0, static_cast<unsigned int>(all_headers.size() - 2));

        auto wHeaders = to_wstring(all_headers);
        if (!WinHttpAddRequestHeaders(hRequest, wHeaders.data(), (DWORD) wHeaders.size(),
            WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON))
            return {};
    }

    if (request.flags & NoRedirect)
    {
        auto flag = WINHTTP_DISABLE_REDIRECTS;
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &flag, sizeof(flag)))
            return {};
    }

    // Retry for several times if fails.
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, request.content.data(), request.content.size(), request.content.size(), 0))
        return {};

    if (!WinHttpReceiveResponse(hRequest, nullptr))
        return {};

    DWORD size = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, nullptr, nullptr, &size, nullptr);

    stl::vector<wchar_t> responseHeaders(size + 1, 0);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, nullptr, responseHeaders.data(), &size, nullptr))
    {
        stl::string response_headers = from_wstring(responseHeaders.data());

        for (unsigned pos = response_headers.find("\r\n", 0) + 2; pos < response_headers.size();)
        {
            unsigned name_start = pos;
            unsigned name_end = response_headers.find(": ", name_start);
            if (name_end == stl::string::npos)
                break;
            unsigned content_start = name_end + 2;
            unsigned content_end = response_headers.find("\r\n", content_start);
            if (content_end == stl::string::npos)
                content_end = static_cast<unsigned int>(response_headers.size());

            response.headers.insert({
                stl::string(response_headers.c_str() + name_start, name_end - name_start),
                stl::string(response_headers.c_str() + content_start, content_end - content_start)
            });
            pos = content_end + 2;
        }
    }

    size = sizeof(response.status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &response.status, &size, nullptr);

    response.content = "";
    stl::vector<unsigned char> buffer;
    do
    {
        size = 0;
        if (WinHttpQueryDataAvailable(hRequest, &size))
        {
            buffer.resize(size, 0);
            {
                DWORD read = 0;
                if (WinHttpReadData(hRequest, buffer.data(), size, &read))
                {
                    response.content.reserve(response.content.size() + read);
                    for (unsigned char c : buffer)
                        response.content.push_back(c);
                }
            }
        }
        else
            return {};
    } while (size > 0);

    //Content-Length

    auto it = response.headers.find("Content-Encoding");
    if (it != response.headers.end() && (*it).second == "gzip")
    {
        stl::string buf;
        auto size = response.content.size() * 10;
        for (int i = 0; i < 3; i++)
        {
            buf.resize(size);

            mini_gzip gz{ };
            mini_gz_init(&gz);
            mini_gz_start(&gz, (void*) response.content.c_str(), response.content.size());

            int len = mini_gz_unpack(&gz, &buf.at(0), buf.size());
            if (len > 0)
            {
                response.content = std::move(buf);
                response.content.resize(static_cast<size_t>(len));
                break;
            }
            else
                size *= 2;
        }
    }

    return response;
}
