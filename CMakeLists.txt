cmake_minimum_required(VERSION 3.16)
project(uds29 VERSION 0.3.0 LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(UDS29_CRYPTO "OPENSSL" CACHE STRING "Crypto backend: OPENSSL, MBEDTLS or CUSTOM (register ops with Uds29_SetCryptoOps)")
set_property(CACHE UDS29_CRYPTO PROPERTY STRINGS OPENSSL MBEDTLS CUSTOM)
set(UDS29_OS "POSIX" CACHE STRING "OS port: POSIX (Linux, QNX) or FREERTOS")
set_property(CACHE UDS29_OS PROPERTY STRINGS POSIX FREERTOS)
option(UDS29_FREERTOS_COMPILE_CHECK "Compile Uds29_Os_FreeRtos.c against FreeRTOS-Kernel (posix port) as an object library" OFF)
option(BUILD_SHARED_LIBS "Build libuds29 as a shared library (default: static)" OFF)
option(UDS29_ENABLE_IDSM "Build the IDSM bridge" OFF)
if(NOT UDS29_CRYPTO MATCHES "^(OPENSSL|MBEDTLS|CUSTOM)$")
    message(FATAL_ERROR "UDS29_CRYPTO must be OPENSSL, MBEDTLS or CUSTOM")
endif()
if(NOT UDS29_OS MATCHES "^(POSIX|FREERTOS)$")
    message(FATAL_ERROR "UDS29_OS must be POSIX or FREERTOS")
endif()

if(UDS29_TOOLCHAIN_STATIC_ONLY AND BUILD_SHARED_LIBS)
    message(FATAL_ERROR "BUILD_SHARED_LIBS is not supported with this toolchain (static library only)")
endif()
include(FetchContent)
include(GNUInstallDirs)
if(BUILD_SHARED_LIBS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON) # also for fetched mbedTLS objects linked into the .so
endif()

# ── Core library: plain C11, static memory (sizes in include/Uds29_Cfg.h), no heap, no exceptions ──
add_library(uds29
    src/Uds29.c
    src/Uds29_Manager.c
    src/Uds29_Codec.c
    src/Uds29_Crypto.c
)
add_library(uds29::uds29 ALIAS uds29)
set_target_properties(uds29 PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)
target_include_directories(uds29 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_options(uds29 PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(uds29 PUBLIC UDS29_CRYPTO_${UDS29_CRYPTO})
foreach(v UDS29_MAX_CERT_LEN UDS29_MAX_CHALLENGE_LEN UDS29_MAX_SIG_LEN UDS29_MAX_MSG_LEN UDS29_LOG_DEPTH)
    if(DEFINED ${v})
        target_compile_definitions(uds29 PUBLIC ${v}=${${v}})
    endif()
endforeach()

# OS port
if(UDS29_OS STREQUAL "POSIX")
    find_package(Threads REQUIRED)
    target_sources(uds29 PRIVATE src/os/Uds29_Os_Posix.c)
    target_link_libraries(uds29 PUBLIC Threads::Threads)
    target_compile_definitions(uds29 PUBLIC $<BUILD_INTERFACE:UDS29_SAMPLE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/certs/sample">) # SAMPLE PKI mode (build tree only)
else()
    # The application's FreeRTOS include directories must be added to the uds29 target.
    target_sources(uds29 PRIVATE src/os/Uds29_Os_FreeRtos.c)
endif()

# Crypto backend
if(UDS29_CRYPTO STREQUAL "OPENSSL")
    find_package(OpenSSL REQUIRED)
    target_sources(uds29 PRIVATE src/crypto/Uds29_Crypto_OpenSsl.c)
    target_link_libraries(uds29 PUBLIC OpenSSL::Crypto)
elseif(UDS29_CRYPTO STREQUAL "MBEDTLS")
    find_package(MbedTLS 3 QUIET)
    if(NOT MbedTLS_FOUND)
        set(UDS29_FETCHED_MBEDTLS TRUE) # its targets cannot be exported: no install rules in this configuration
        set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
        set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
        set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(mbedtls
            GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
            GIT_TAG        v3.6.2
            GIT_SHALLOW    TRUE
            GIT_SUBMODULES framework) # the only submodule; its CMake is required even without tests
        FetchContent_MakeAvailable(mbedtls)
    endif()
    target_sources(uds29 PRIVATE src/crypto/Uds29_Crypto_MbedTls.c)
    if(TARGET MbedTLS::mbedx509)
        target_link_libraries(uds29 PUBLIC MbedTLS::mbedx509 MbedTLS::mbedcrypto)
    else()
        target_link_libraries(uds29 PUBLIC mbedx509 mbedcrypto)
    endif()
endif()

# ── Install / package (find_package(uds29) -> uds29::uds29) ──
if(NOT UDS29_FETCHED_MBEDTLS)
    include(CMakePackageConfigHelpers)
    set(UDS29_CONFIG_DEPS "")
    if(UDS29_OS STREQUAL "POSIX")
        string(APPEND UDS29_CONFIG_DEPS "find_dependency(Threads)\n")
    endif()
    if(UDS29_CRYPTO STREQUAL "OPENSSL")
        string(APPEND UDS29_CONFIG_DEPS "find_dependency(OpenSSL)\n")
    elseif(UDS29_CRYPTO STREQUAL "MBEDTLS")
        string(APPEND UDS29_CONFIG_DEPS "find_dependency(MbedTLS 3)\n")
    endif()
    set(UDS29_PC_LIBS_PRIVATE "")
    if(UDS29_CRYPTO STREQUAL "OPENSSL")
        set(UDS29_PC_LIBS_PRIVATE "-lcrypto")
    elseif(UDS29_CRYPTO STREQUAL "MBEDTLS")
        set(UDS29_PC_LIBS_PRIVATE "-lmbedx509 -lmbedcrypto")
    endif()
    if(UDS29_OS STREQUAL "POSIX")
        string(APPEND UDS29_PC_LIBS_PRIVATE " -lpthread")
    endif()
    set(UDS29_PC_DEFS "-DUDS29_CRYPTO_${UDS29_CRYPTO}")
    foreach(v UDS29_MAX_CERT_LEN UDS29_MAX_CHALLENGE_LEN UDS29_MAX_SIG_LEN UDS29_MAX_MSG_LEN UDS29_LOG_DEPTH)
        if(DEFINED ${v})
            string(APPEND UDS29_PC_DEFS " -D${v}=${${v}}")
        endif()
    endforeach()
    file(RELATIVE_PATH UDS29_PC_UP "/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "/") # relocatable .pc: prefix = ${pcfiledir}/<up>
    set(UDS29_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/uds29)

    install(TARGETS uds29 EXPORT uds29Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES include/Uds29.h include/Uds29_Types.h include/Uds29_Transport.h include/Uds29_Cfg.h
                  include/Uds29_Codec.h include/Uds29_Crypto.h include/Uds29_Os.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(EXPORT uds29Targets NAMESPACE uds29:: DESTINATION ${UDS29_CMAKE_DIR})
    configure_package_config_file(cmake/uds29Config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/uds29Config.cmake
        INSTALL_DESTINATION ${UDS29_CMAKE_DIR})
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/uds29ConfigVersion.cmake
        VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
    configure_file(cmake/uds29.pc.in ${CMAKE_CURRENT_BINARY_DIR}/uds29.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/uds29Config.cmake ${CMAKE_CURRENT_BINARY_DIR}/uds29ConfigVersion.cmake
            DESTINATION ${UDS29_CMAKE_DIR})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/uds29.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
else()
    message(STATUS "uds29: mbedTLS was fetched, install rules disabled (install mbedTLS 3.x to get a package)")
endif()

# ── Host-only tools: simulated ECU, CLI, tests (need a built-in crypto backend and POSIX) ──
if(UDS29_OS STREQUAL "POSIX" AND NOT UDS29_CRYPTO STREQUAL "CUSTOM")
    add_library(uds29_sim STATIC src/Uds29_SimEcu.cpp)
    target_link_libraries(uds29_sim PUBLIC uds29)
    target_compile_options(uds29_sim PRIVATE -Wall -Wextra -Wpedantic)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    include(GoogleTest)
    add_executable(uds29_cli apps/uds29_cli/main.cpp)
    target_link_libraries(uds29_cli PRIVATE uds29_sim)
    target_compile_options(uds29_cli PRIVATE -Wall -Wextra -Wpedantic)
    if(NOT UDS29_FETCHED_MBEDTLS)
        install(TARGETS uds29_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()

    add_executable(linux_app examples/linux_app.c)
    target_link_libraries(linux_app PRIVATE uds29_sim)
    target_compile_options(linux_app PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME example_linux_app COMMAND linux_app)

    # Optional IDSM bridge (builds only IdsM from the AUTOSAR IDSM toolkit, not IdsRm/curl)
    set(IDSM_TOOLKIT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../autosar-idsm-toolkit" CACHE PATH "Path to autosar-idsm-toolkit")
    set(UDS29_TESTS test_codec test_pki test_session test_limits test_async)
    if(UDS29_ENABLE_IDSM)
        add_library(idsm_core STATIC ${IDSM_TOOLKIT_DIR}/src/IdsM.c ${IDSM_TOOLKIT_DIR}/src/IdsM_Manager.cpp)
        target_include_directories(idsm_core PUBLIC ${IDSM_TOOLKIT_DIR}/include)
        target_link_libraries(idsm_core PUBLIC Threads::Threads)
        add_library(uds29_idsm STATIC src/Uds29_IdsM.c)
        target_link_libraries(uds29_idsm PUBLIC uds29 idsm_core)
        target_compile_options(uds29_idsm PRIVATE -Wall -Wextra -Wpedantic)
        target_link_libraries(uds29_cli PRIVATE uds29_idsm)
        target_compile_definitions(uds29_cli PRIVATE UDS29_WITH_IDSM)
        list(APPEND UDS29_TESTS test_idsm_bridge)
    endif()

    foreach(t ${UDS29_TESTS})
        add_executable(${t} tests/${t}.cpp)
        target_link_libraries(${t} PRIVATE uds29_sim GTest::gtest_main)
        if(t STREQUAL test_idsm_bridge)
            target_link_libraries(${t} PRIVATE uds29_idsm)
        endif()
        target_compile_options(${t} PRIVATE -Wall -Wextra)
        gtest_discover_tests(${t})
    endforeach()
endif()

# ── FreeRTOS compile check: no target here, so only prove the OS port builds against the real kernel headers ──
if(UDS29_FREERTOS_COMPILE_CHECK)
    FetchContent_Declare(freertos_kernel
        GIT_REPOSITORY https://github.com/FreeRTOS/FreeRTOS-Kernel.git
        GIT_TAG        V11.1.0
        GIT_SHALLOW    TRUE
        GIT_SUBMODULES ""
        SOURCE_SUBDIR  none) # populate only: the kernel's own CMake project is not used
    FetchContent_MakeAvailable(freertos_kernel)
    add_library(uds29_os_freertos_check OBJECT src/os/Uds29_Os_FreeRtos.c examples/freertos_task.c)
    target_include_directories(uds29_os_freertos_check PRIVATE include ports/freertos)
    target_include_directories(uds29_os_freertos_check SYSTEM PRIVATE
        ${freertos_kernel_SOURCE_DIR}/include
        ${freertos_kernel_SOURCE_DIR}/portable/ThirdParty/GCC/Posix)
    target_compile_options(uds29_os_freertos_check PRIVATE -Wall -Wextra -Wpedantic)
endif()
