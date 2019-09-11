#!/usr/bin/env python3
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
import argparse
import hashlib
import sys
import os
import random
import zlib


def rc4crypt(data, key):
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
    return data


def bin2h(file_in, file_out, name):

    try:
        if os.path.getmtime(sys.argv[1]) <= os.path.getmtime(sys.argv[2]):
            return
    except WindowsError:
        pass

    fi = open(file_in, 'rb')
    fo = open(file_out, 'w+')
    if fi is not None and fo is not None:
        bin = bytearray(fi.read())

        fo.write('// {}\n'.format(hashlib.sha1(bin).hexdigest()))
        fo.write('#pragma once\n\n')
        fo.write('const unsigned RSRC_%s_SIZE = %d;\n' % (name, len(bin)))
        bin = bytearray(zlib.compress(bin))

        random.seed()
        key = []
        for _x in range(20):
            key.append(random.getrandbits(8) & 0xFF)
        fo.write('const unsigned char RSRC_%s_KEY[] = { ' % name)
        for k in key:
            fo.write('0x%02X, ' % k)
        fo.write('};\n')
        fo.write('const unsigned RSRC_%s_KEY_SIZE = sizeof(RSRC_%s_KEY);\n\n' % (name, name))
        rc4crypt(bin, key)

        fo.write('unsigned char RSRC_%s_DATA[] = {\n\t' % name)

        li = 1
        for i in range(len(bin)):
            fo.write('0x%02X, ' % bin[i])
            if li == 15:
                fo.write('\n\t')
                li = 0
            li += 1
        fo.write('\r\n};\n')
        fo.write('const unsigned RSRC_%s_DATA_SIZE = sizeof(RSRC_%s_DATA);\n\n' % (name, name))
        fo.close()
        fi.close()
    else:
        print('Either of files can not be accessed!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('name')
    args = parser.parse_args()
    bin2h(args.input, args.output, args.name)
