# Bare-metal Cortex-M build of the core library (static only). Typical use:
#   cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi.cmake \
#         -DUDS29_OS=FREERTOS -DUDS29_CRYPTO=CUSTOM
# Add your FreeRTOS include directories to the uds29 target (target_include_directories) from the parent project, or pass
# -DCMAKE_C_FLAGS="-I<kernel>/include -I<port> -I<dir with FreeRTOSConfig.h>". Adjust the -mcpu/-mfpu flags to your part.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY) # no linker script needed for compiler checks
set(CMAKE_C_FLAGS_INIT "-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -ffunction-sections -fdata-sections")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(UDS29_TOOLCHAIN_STATIC_ONLY ON)
