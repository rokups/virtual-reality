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

add_library(ntdll INTERFACE)
target_include_directories(ntdll INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    if (NOT EXISTS libntdll86.a)
        execute_process(COMMAND dlltool -d ${CMAKE_CURRENT_SOURCE_DIR}/ntdll86.def -l libntdll86.a -k -f--32)
    endif ()
    target_link_libraries(ntdll INTERFACE ${CMAKE_BINARY_DIR}/libntdll86.a)
else ()
    if (NOT EXISTS libntdll64.a)
        execute_process(COMMAND dlltool -d ${CMAKE_CURRENT_SOURCE_DIR}/ntdll64.def -l libntdll64.a)
    endif ()
    target_link_libraries(ntdll INTERFACE ${CMAKE_BINARY_DIR}/libntdll64.a)
endif ()
