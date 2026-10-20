# FreeRTOS guide

> **Untested on a target.** There is no FreeRTOS target or SDK in the development environment. What *is* verified:
> `src/os/Uds29_Os_FreeRtos.c` and `examples/freertos_task.c` compile warning-free against FreeRTOS-Kernel V11.1.0
> headers (POSIX/GCC simulator port) via `-DUDS29_FREERTOS_COMPILE_CHECK=ON`, which is part of CI. Nothing was linked,
> run, or built with `arm-none-eabi-gcc`. Stack and heap figures below are estimates, not measurements.

## Prerequisites

- FreeRTOS kernel with `configUSE_RECURSIVE_MUTEXES 1` and `configSUPPORT_STATIC_ALLOCATION 1` (the OS port creates its lock with `xSemaphoreCreateRecursiveMutexStatic`; you must also provide the static-allocation idle/timer memory callbacks if your config requires them)
- A crypto backend for the target: mbedTLS 3.x (ECDSA P-256 only) or `CUSTOM` ops (HSM / SE / PKCS#11) registered with `Uds29_SetCryptoOps` before the first `Uds29_SetPki` / `Uds29Srv_Init`
- Certificates reachable by your crypto backend. The built-in mbedTLS backend loads **files** (PEM or DER); on a target without a file system use `CUSTOM` ops, where `load_identity` can read from flash
- `arm-none-eabi-gcc` for Cortex-M builds, CMake 3.16+

## Build

Compile check on the host (what CI does):

```sh
cmake -S . -B build -DUDS29_FREERTOS_COMPILE_CHECK=ON && cmake --build build -j
```

Cross build of the library (static only, core only: no sim, CLI or tests):

```sh
cmake -S . -B build-arm \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi.cmake \
  -DUDS29_OS=FREERTOS -DUDS29_CRYPTO=CUSTOM -DUDS29_ROLE=SERVER
cmake --build build-arm -j
```

`UDS29_ROLE` picks the side(s): an ECU typically needs `SERVER`, a gateway or tester `CLIENT`. FreeRTOS include
directories must be added to the `uds29` target by the parent project (`target_include_directories(uds29 PRIVATE ...)`)
or passed with `-DCMAKE_C_FLAGS="-I<kernel>/include -I<port> -I<dir of FreeRTOSConfig.h>"`. Adjust `-mcpu`/`-mfpu` in the toolchain file.

## Install

Easiest: add this repository as a subdirectory of your firmware build (`add_subdirectory(UDS-29-auth-toolkit)`) and link
`uds29::uds29`. `cmake --install` also works and gives a relocatable `find_package(uds29)` package.

## Use in your project

Memory (defaults from `Uds29_Cfg.h`, x86-64 figures; static RAM, no heap):

| Role | Static RAM | Reduce with |
| --- | --- | --- |
| Client | about 44 KB, 41.7 KB of it the exchange log | `UDS29_LOG_DEPTH` (4 gives about 8 KB total) |
| Server | about 5.3 KB | `UDS29_MAX_CERT_LEN`, `UDS29_MAX_MSG_LEN` |

Plus the stack of the calling task: crypto operations are the deep part; budget several KB (the README example uses 2048 words
as a starting point). `Uds29_Os_Lock` is a mutex and **not ISR-safe**: never call any `Uds29_*` / `Uds29Srv_*` function from an ISR.

Server (ECU) task skeleton, fed by your CAN-TP / DoIP stack:

```c
static void DiagTask(void* arg) {
    Uds29Srv_ConfigType c = {0};
    c.pki = (Uds29_PkiConfigType){UDS29_PKI_USER, "ca.der", "ecu.der", "ecu.key", UDS29_PKI_FORMAT_DER}; /* or CUSTOM ops */
    c.auth_timeout_ms = 60000;
    Uds29Srv_Init(&c);
    for (;;) {
        Uds29Srv_MainFunction();                              /* auth timeout */
        if (TpReceive(req, &req_len, pdMS_TO_TICKS(10)))      /* a full SID 0x29 request */
            { resp_len = sizeof resp; if (Uds29Srv_HandleRequest(req, req_len, resp, &resp_len) == E_OK) TpSend(resp, resp_len); }
    }
}
```

Client (tester) skeleton: `examples/freertos_task.c` (non-blocking flow: `Uds29_StartAuthentication`, then a loop of
`Uds29_MainFunction()` and `Uds29_RxIndication()` fed from a queue that the CAN ISR fills).

Time base: `Uds29_Os_GetTimeMs` returns the tick count scaled to milliseconds; the auth timeout and the P2 timeout
resolution are the period of `MainFunction`.

## Run

On the target only; there is no simulator run in this repository (the demos use POSIX sockets). Run your task, authenticate
from a tester, and watch `Uds29Srv_GetState()` / the server event callback.

## Confirm it works

- Verified here: the compile check builds with no warnings (`cmake --build build` prints no `warning:`; target `uds29_os_freertos_check`).
- On your target (not verified): after a successful bidirectional authentication from a tester, `Uds29Srv_IsAuthenticated()` returns `true` and the event callback saw `CERT_SENT` then `AUTHENTICATED`; with `auth_timeout_ms` set it returns `false` again after that time without further requests.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Link error `xQueueCreateMutexStatic` / `xQueueTakeMutexRecursive` undefined | enable `configUSE_RECURSIVE_MUTEXES` and `configSUPPORT_STATIC_ALLOCATION` |
| `FreeRTOS.h: No such file` | add the kernel and port include directories to target `uds29` |
| `UDS29_TOOLCHAIN_STATIC_ONLY` error with `BUILD_SHARED_LIBS` | the arm-none-eabi toolchain is static-only by design |
| `Uds29Srv_Init` / `Uds29_SetPki` returns `E_NOT_OK` | crypto backend cannot read the files/handles (no file system?), key does not match the cert, chain not valid, or buffer limits exceeded (`UDS29_MAX_CERT_LEN`) |
| Hard fault inside crypto | task stack too small |
| mbedTLS: Ed25519 certificates rejected | backend supports ECDSA P-256 only |
