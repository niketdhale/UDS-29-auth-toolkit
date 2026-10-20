cmake_minimum_required(VERSION 3.16)
project(uds-29-auth-toolkit LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

# Core library: mix of C (AUTOSAR-style API) and C++ (manager, codec, PKI, sim ECU)
add_library(uds29 STATIC
    src/Uds29.c
    src/Uds29_Manager.cpp
    src/Uds29_Codec.cpp
    src/Uds29_Pki.cpp
    src/Uds29_SimEcu.cpp
)
target_include_directories(uds29 PUBLIC include)
target_link_libraries(uds29 PUBLIC OpenSSL::Crypto)
target_compile_definitions(uds29 PUBLIC UDS29_SAMPLE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/certs/sample")
target_compile_options(uds29 PRIVATE -Wall -Wextra -Wpedantic)

# Tests
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)
foreach(t test_codec test_pki test_session)
    add_executable(${t} tests/${t}.cpp)
    target_link_libraries(${t} PRIVATE uds29 GTest::gtest_main)
    target_compile_options(${t} PRIVATE -Wall -Wextra)
    gtest_discover_tests(${t})
endforeach()
