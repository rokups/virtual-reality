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


#include <stdint.h>

// ICMP packet types
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRE 11
#define ICMP_ECHO_REQUEST 8

// Minimum ICMP packet size, in bytes
#define ICMP_MIN 8

enum IcmpFlags
{
    ICMP_PORT_OPEN = 1,
    ICMP_PORT_CLOSE = 2,
    ICMP_MSF_CONNECT = 4,
    ICMP_FLAGS_MAX
};

#pragma pack(1)

#ifdef _WIN32
// The IP header
struct iphdr
    {
    uint8_t ihl : 4;       // Length of the header in dwords
    uint8_t version : 4;   // Version of IP
    uint8_t tos;           // Type of service
    uint16_t tot_len;      // Length of the packet in dwords
    uint16_t id;           // unique identifier
    uint16_t frag_off;     // Flags
    uint8_t ttl;           // Time to live
    uint8_t protocol;      // Protocol number (TCP, UDP etc)
    uint16_t check;        // IP checksum
    uint32_t saddr;
    uint32_t daddr;
};

// ICMP header
struct icmphdr {
    uint8_t type;          // ICMP packet type
    uint8_t code;          // Type sub code
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};
#else
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#endif

#pragma pack()

static uint16_t icmp_checksum(uint16_t* buffer, int size)
{
    unsigned long cksum = 0;

    // Sum all the words together, adding the final byte if size is odd
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if (size) {
        cksum += *(uint16_t*)buffer;
    }

    // Do a little shuffling
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    // Return the bitwise complement of the resulting mishmash
    return (uint16_t)(~cksum);
}
