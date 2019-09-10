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

cmake_minimum_required(VERSION 3.8)

project(VR)

include(ucm.cmake)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 17)
ucm_set_runtime(STATIC)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (NOT WIN32)
    message(FATAL_ERROR "This project is meant for Windows platform only")
endif ()

if (MSVC)
	# Disable buffer security checks
    add_compile_options(/GS-)
	# Disable exceptions
    ucm_replace_flag(/EHs?c? /EHs-c- REGEX)
	# Disable RTTI
    ucm_replace_flag(/GR /GR-)
	# Enable function level linking
    add_compile_options(/Gy)
	# Enable link time code generation a removal of unreferenced code
	ucm_add_linker_flags(EXE SHARED MODULE /LTCG /OPT:REF)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif ()

if (MINGW)
    set (EXTRA_LINKER_FLAGS "-nodefaultlibs -dynamic -ffunction-sections -fdata-sections -Wl,-gc-sections")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${EXTRA_LINKER_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${EXTRA_LINKER_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")
    set (CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} -s -DNDEBUG")
    set (CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -s -DNDEBUG")
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
    set (CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -D_DEBUG")
    set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -D_DEBUG")
endif ()

add_subdirectory(dep)
add_subdirectory(src)
