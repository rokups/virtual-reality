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

#ifdef __cplusplus
inline unsigned operator "" _sec(unsigned long long int n)  { return static_cast<unsigned int>(n * 1000); }
inline unsigned operator "" _min(unsigned long long int n)  { return static_cast<unsigned int>(n * 60 * 1000); }
inline unsigned operator "" _hour(unsigned long long int n) { return static_cast<unsigned int>(n * 60 * 60 * 1000); }
#endif

// 64bit integer. A key used for obfuscating various data.
#define vr_shared_key 0x982147b5bea3f6c2ull

// String. Client id to be used for scanning imgur.
#define vr_imgur_client_id "546c25a59c58ad7"

// String. imgur.com tag in which http module will look for images with encoded commands
#define vr_imgur_tag "png"

// Integer. Time between imgur tag queries
#define vr_imgur_tag_query_time 15_min

// Integer. Random time added to imgur tag query time
#define vr_imgur_tag_query_time_jitter 1_min


// Private variables, do not modify.
#define vr_mutant_main_instance 0x1000
