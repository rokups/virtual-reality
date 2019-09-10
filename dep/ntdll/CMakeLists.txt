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
    set (NTDLL_ARCH 86)
else ()
    set (NTDLL_ARCH 64)
endif ()
if (MSVC)
    find_program(LIB_EXE lib)
    if (NOT LIB_EXE)
        message(FATAL_ERROR "lib.exe was not found. Run CMake from 'Developer Command Prompt'")
    endif ()
    if (NOT EXISTS ${CMAKE_BINARY_DIR}/ntdll${NTDLL_ARCH}.lib)
        execute_process(COMMAND lib /def:${CMAKE_CURRENT_SOURCE_DIR}/ntdll${NTDLL_ARCH}.def /out:${CMAKE_BINARY_DIR}/ntdll${NTDLL_ARCH}.lib /machine:x${NTDLL_ARCH})
    endif ()
    target_link_libraries(ntdll INTERFACE ${CMAKE_BINARY_DIR}/ntdll${NTDLL_ARCH}.lib)
else ()
    find_program(DLLTOOL_EXE dlltool)
    if (NOT DLLTOOL_EXE)
        message(FATAL_ERROR "dlltool.exe was not found.")
    endif ()
    if (CMAKE_SIZEOF_VOID_P EQUAL 4)
        set (NTDLL_PARAM 32)
    else ()
        set (NTDLL_PARAM 64)
    endif ()
    if (NOT EXISTS ${CMAKE_BINARY_DIR}/libntdll${NTDLL_ARCH}.a)
        execute_process(COMMAND ${DLLTOOL_EXE} -d ${CMAKE_CURRENT_SOURCE_DIR}/ntdll${NTDLL_ARCH}.def -l ${CMAKE_BINARY_DIR}/libntdll${NTDLL_ARCH}.a -k -f--${NTDLL_PARAM})
    endif ()
endif ()

