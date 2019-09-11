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
set(OUTPUT_BIN_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if (MSVC)
	set(OUTPUT_BIN_DIRECTORY ${OUTPUT_BIN_DIRECTORY}/$<CONFIG>)
endif ()
include_directories(${OUTPUT_BIN_DIRECTORY})

set(CMAKE_CXX_STANDARD 17)
ucm_set_runtime(STATIC)

if (NOT WIN32)
    message(FATAL_ERROR "This project is meant for Windows platform only")
endif ()

if (MSVC)
	if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../VC-LTL")
		set(SupportWinXP "true")
		add_definitions(-D_DISABLE_DEPRECATE_LTL_MESSAGE=1)
		include("../VC-LTL/VC-LTL helper for cmake.cmake")
	endif ()
    # Disable buffer security checks
    add_compile_options(/GS-)
    # Disable exceptions
    ucm_replace_flag(/EHs?c? /EHs-c- REGEX)
    # Disable RTTI
    ucm_replace_flag(/GR /GR-)
    # Enable function level linking
    add_compile_options(/Gy)
    # Enable removal of unreferenced code
    ucm_add_linker_flags(EXE SHARED MODULE CONFIG Release MinSizeRel /OPT:REF)
    # Silence useless warnings
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS)
    # Enable runtime code generation
    ucm_add_flags(CONFIG Release MinSizeRel /RTCG)
endif ()

if (MINGW)
    ucm_add_linker_flags(SHARED EXE -nodefaultlibs -dynamic -ffunction-sections -fdata-sections -Wl,-gc-sections)
    ucm_add_flags(CXX -fno-rtti -fno-exceptions)
    ucm_add_flags(CONFIG MinSizeRel -s)
endif ()

add_definitions(-D_NO_NTDLL_CRT_)

add_compile_options(
    $<$<CONFIG:Debug>:-DDEBUG=1>
    $<$<CONFIG:RelWithDebInfo>:-DDEBUG=1>
    $<$<CONFIG:Release>:-DNDEBUG=1>
    $<$<CONFIG:MinSizeRel>:-DNDEBUG=1>
)

macro (export_reflective_loader TARGET)
	if (CMAKE_SIZEOF_VOID_P EQUAL 4)
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS "/INCLUDE:_ReflectiveLoader@4")
	else ()
		set_target_properties(${TARGET} PROPERTIES LINK_FLAGS "/INCLUDE:ReflectiveLoader")
	endif ()
endmacro ()

add_subdirectory(dep)
add_subdirectory(src)
