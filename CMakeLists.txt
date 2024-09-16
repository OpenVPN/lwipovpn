cmake_minimum_required(VERSION 3.14)

include(CheckSymbolExists)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release;ASAN")

# AddressSanitize - use CXX=clang++ CC=clang cmake -DCMAKE_BUILD_TYPE=asan to build with ASAN
set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
        FORCE)
set(CMAKE_CXX_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
        FORCE)

project(lwipovpn)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set(LWIP_CONTRIB_DIR ${LWIP_DIR}/contrib/)

set (LWIP_INCLUDE_DIRS
        "${LWIP_DIR}/src/include"
        "${LWIP_DIR}/contrib"
        "${LWIP_DIR}/contrib/ports/unix/port/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/conf"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set (LWIP_DEFINITIONS LWIP_DEBUG=1)

set(LWIP_OVPN_INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/app"
        "${CMAKE_CURRENT_SOURCE_DIR}/netif"
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# add a variant of lwipcontribportunix that does not include the probelmatic sio.c and to avoid pulling in unneeded sources
add_library(lwipcontribunixsys EXCLUDE_FROM_ALL ${lwipcontribportunix_SRCS})
target_include_directories(lwipcontribunixsys PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_compile_options(lwipcontribunixsys PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcontribunixsys PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(lwipcontribunixsys PUBLIC ${LWIP_MBEDTLS_LINK_LIBRARIES})
target_link_libraries(lwipcontribunixsys PUBLIC Threads::Threads)


if (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    target_compile_definitions(lwipcontribunixsys PUBLIC -DLWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS)
endif ()

# Avoid format specifies type 'unsigned long' but the argument has type 'clock_t' (aka 'int') warning
target_compile_options(lwipcontribunixsys PRIVATE -Wno-format)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_library(LIBUTIL util)
    find_library(LIBRT rt)
    target_link_libraries(lwipcontribunixsys PUBLIC ${LIBUTIL} ${LIBPTHREAD} ${LIBRT})
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(LIBUTIL util)
    target_link_libraries(lwipcontribunixsys PUBLIC ${LIBUTIL})
endif()


add_executable(lwipovpn
        app/unixaf_app.c
        netif/unixaf.c
        netif/unixaf.h
        netif/unixaf_host.c
        netif/unixaf_host.h
)

# C doesn't seem to have a good easy to use random function. Use arc4random if available otherwise rand
check_symbol_exists(arc4random stdlib.h HAVE_ARC4RANDOM)

# we do not care about C90 compatibility in lwipovpn since OpenVPN itself requires C11
set(LWIP_COMPILER_FLAGS_OVPN  ${LWIP_COMPILER_FLAGS})
LIST(REMOVE_ITEM LWIP_COMPILER_FLAGS_OVPN $<$<COMPILE_LANGUAGE:C>:-Wc90-c99-compat>)
LIST(REMOVE_ITEM LWIP_COMPILER_FLAGS_OVPN -Waggregate-return)

target_include_directories(lwipovpn PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_OVPN_INCLUDE_DIRS})
target_compile_options(lwipovpn PRIVATE ${LWIP_COMPILER_FLAGS_OVPN})
target_compile_definitions(lwipovpn PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
if (NOT "${HAVE_ARC4RANDOM}")
    target_compile_definitions(lwipovpn PRIVATE -DARC4RANDOM_MISSING)
endif()
target_link_libraries(lwipovpn PRIVATE ${LWIP_SANITIZER_LIBS} lwipcontribexamples lwipcontribapps lwipcontribaddons lwipallapps lwipcontribunixsys lwipcore lwipmbedtls)

