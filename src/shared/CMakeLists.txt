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

# Generate config and copy vr.py to bin dir for distribution
add_custom_command(
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/vr-config.h
    COMMAND ${CMAKE_COMMAND} -DVR_CONFIG=${VR_CONFIG} -DVR_SOURCE_DIR=${VR_SOURCE_DIR}
	        -DOUTPUT_BIN_DIRECTORY=${OUTPUT_BIN_DIRECTORY} -P ${VR_SOURCE_DIR}/configure.cmake
    COMMAND ${CMAKE_COMMAND} -E copy ${VR_SOURCE_DIR}/vr.py ${OUTPUT_BIN_DIRECTORY}/vr.py
    COMMAND ${CMAKE_COMMAND} -E copy ${VR_SOURCE_DIR}/service.ps1 ${OUTPUT_BIN_DIRECTORY}/service.ps1)
set_source_files_properties(${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/vr-config.h PROPERTIES GENERATED TRUE)

# Build shared library
file(GLOB_RECURSE SOURCE_FILES *.c *.cpp *.h *.hpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	enable_language(ASM_MASM)
	list (APPEND SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/free_exit.asm)
endif ()
add_library(shared STATIC ${SOURCE_FILES} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_CFG_INTDIR}/vr-config.h)
if (NOT MSVC)
    target_compile_options(shared PRIVATE -Wno-multichar)
endif ()
target_link_libraries(shared PUBLIC mini-gzip miniz picopng tinystl tiny-json crypt32 winhttp ntdll)
