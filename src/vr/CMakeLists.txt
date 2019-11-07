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

file(GLOB_RECURSE SOURCE_FILES *.h *.hpp *.cpp)
if (VR_PAYLOAD_SERVICE)
    add_library(vr MODULE ${SOURCE_FILES} ${VR_CONFIG})
    target_compile_definitions(vr PRIVATE -DVR_PAYLOAD_SERVICE=1)
else ()
    add_executable(vr WIN32 ${SOURCE_FILES} ${VR_CONFIG})
    export_reflective_loader(vr)
endif ()
target_link_libraries(vr shared tiny-json ws2_32 iphlpapi)
export_reflective_loader(vr)
add_dependencies(vr gts stager)
if (NOT MSVC)
    target_link_libraries(vr mingw32 gcc mingwex gcc msvcrt)   # CRT
endif ()
