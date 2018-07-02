project (sss)
cmake_minimum_required(VERSION 3.5.1)

set(TARGET_GROUP main CACHE STRING "Group to build")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -m64 -std=c99 \
    -pedantic	-Wall -Wshadow -Wpointer-arith -Wcast-qual \
    -Wformat -Wformat-security -Werror=format-security \
    -Wstrict-prototypes -Wmissing-prototypes -D_FORTIFY_SOURCE=2 \
    -fPIC -fno-strict-overflow" )



add_subdirectory(src)

if(TARGET_GROUP STREQUAL main)
    message(SKIP "Nothing to do...")
elseif(TARGET_GROUP STREQUAL test)
    include(CTest)
    add_subdirectory(tests)
else()
    message(FATAL_ERROR "Given TARGET_GROUP unknown")
endif()
