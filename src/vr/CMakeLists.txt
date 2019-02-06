
file(GLOB_RECURSE SOURCE_FILES *.h *.cpp)
add_executable(payload WIN32 ${SOURCE_FILES})
target_link_libraries(payload shared tiny-json ws2_32 iphlpapi)
target_link_libraries(payload mingw32 gcc mingwex gcc msvcrt)   # CRT
