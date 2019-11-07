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

file(GLOB_RECURSE SOURCE_FILES *.h *.cpp)
#add_library(keylogger SHARED ${SOURCE_FILES})
add_executable(keylogger ${SOURCE_FILES})
target_link_libraries(keylogger PUBLIC shared psapi)
export_reflective_loader(keylogger)
if (NOT MSVC)
    target_link_libraries(keylogger mingw32 gcc mingwex gcc msvcrt)   # CRT
endif ()

find_package (Python COMPONENTS Interpreter REQUIRED)
add_custom_command(TARGET keylogger POST_BUILD
    COMMAND ${Python_EXECUTABLE} -B ${CMAKE_SOURCE_DIR}/script/bin2h.py $<TARGET_FILE:keylogger> ${OUTPUT_BIN_DIRECTORY}/keylogger.dll.h KEYLOGGER
    COMMENT "Creating keylogger.dll.h"
)
