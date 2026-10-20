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
add_executable(uds29_cli apps/uds29_cli/main.cpp)
target_link_libraries(uds29_cli PRIVATE uds29)
target_compile_options(uds29_cli PRIVATE -Wall -Wextra -Wpedantic)

# Optional IDSM bridge (builds only IdsM from the AUTOSAR IDSM toolkit, not IdsRm/curl)
option(UDS29_ENABLE_IDSM "Build the IDSM bridge" OFF)
set(IDSM_TOOLKIT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../autosar-idsm-toolkit" CACHE PATH "Path to autosar-idsm-toolkit")
set(UDS29_TESTS test_codec test_pki test_session)
if(UDS29_ENABLE_IDSM)
    find_package(Threads REQUIRED)
    add_library(idsm_core STATIC ${IDSM_TOOLKIT_DIR}/src/IdsM.c ${IDSM_TOOLKIT_DIR}/src/IdsM_Manager.cpp)
    target_include_directories(idsm_core PUBLIC ${IDSM_TOOLKIT_DIR}/include)
    target_link_libraries(idsm_core PUBLIC Threads::Threads)
    add_library(uds29_idsm STATIC src/Uds29_IdsM.cpp)
    target_link_libraries(uds29_idsm PUBLIC uds29 idsm_core)
    target_compile_options(uds29_idsm PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(uds29_cli PRIVATE uds29_idsm)
    target_compile_definitions(uds29_cli PRIVATE UDS29_WITH_IDSM)
    list(APPEND UDS29_TESTS test_idsm_bridge)
endif()

foreach(t ${UDS29_TESTS})
    add_executable(${t} tests/${t}.cpp)
    target_link_libraries(${t} PRIVATE uds29 GTest::gtest_main)
    if(t STREQUAL test_idsm_bridge)
        target_link_libraries(${t} PRIVATE uds29_idsm)
    endif()
    target_compile_options(${t} PRIVATE -Wall -Wextra)
    gtest_discover_tests(${t})
endforeach()
