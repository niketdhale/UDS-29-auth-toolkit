# QNX SDP 7.x / 8.0 cross build for aarch64. Source the SDP environment first (qnxsdp-env.sh sets QNX_HOST/QNX_TARGET).
#   cmake -S . -B build-qnx -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/qnx-aarch64le.cmake
# Default UDS29_OS=POSIX applies (QNX is POSIX); host-only tests/CLI/sim need a crypto library for QNX, use
# -DUDS29_CRYPTO=MBEDTLS (installed for the target) or CUSTOM. Not tested by CI.
if(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})
    message(FATAL_ERROR "QNX_HOST / QNX_TARGET not set: source qnxsdp-env.sh")
endif()
set(CMAKE_SYSTEM_NAME QNX)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER   $ENV{QNX_HOST}/usr/bin/qcc)
set(CMAKE_CXX_COMPILER $ENV{QNX_HOST}/usr/bin/q++)
set(CMAKE_C_COMPILER_TARGET   gcc_ntoaarch64le)
set(CMAKE_CXX_COMPILER_TARGET gcc_ntoaarch64le)
set(CMAKE_FIND_ROOT_PATH $ENV{QNX_TARGET} $ENV{QNX_TARGET}/aarch64le)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
