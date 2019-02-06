#!/usr/bin/env python
#
# MIT License
#
# Copyright (c) 2019 Rokas Kupstys
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
import os
import socket
import struct


ICMP_ECHO_REQUEST = 8


class PingError(Exception):
    pass


def icmp_checksum(packet):
    checksum = 0
    for i in range(0, len(packet) - 1, 2):
        checksum += struct.unpack('<H', packet[i:i + 2])[0]

    # Last byte for odd-length packets.
    if len(packet) % 2:
        checksum += packet[-1]

    checksum &= 0xFFFFFFFF
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    checksum = socket.htons(checksum)
    return checksum


def send_ping(address, payload=None, seq_number=0, id=None):
    if payload is None:
        payload = b'PING' * 16

    if id is None:
        id = os.getpid()

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        # Send ICMP_ECHO_REQUEST
        checksum = 0
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, id, seq_number)
        packet = header + payload
        checksum = icmp_checksum(packet)
        packet = packet[:2] + struct.pack('!H', checksum) + packet[4:]
        s.sendto(packet, (address, 0))
    except socket.error as e:
        raise PingError()
    finally:
        if s is not None:
            s.close()
