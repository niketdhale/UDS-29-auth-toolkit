# QNX guide

> **Untested.** There is no QNX SDP or target in the development environment. Nothing in this guide was built or run
> on QNX. What is known: the code uses only POSIX APIs (pthreads, `clock_gettime`, BSD sockets for the demos) that
> QNX provides, and the Linux build is warning-free. The toolchain file `cmake/toolchains/qnx-aarch64le.cmake` has
> never been executed. Expect to adjust paths and flags.

## Prerequisites

- QNX Software Development Platform 7.x or 8.0 on a Linux host, environment sourced (`source ~/qnx/qnxsdp-env.sh`; sets `QNX_HOST`, `QNX_TARGET`)
- CMake 3.16+
- A crypto library built for the QNX target: mbedTLS 3.x (`-DUDS29_CRYPTO=MBEDTLS`, `find_package(MbedTLS 3)` must find it under `QNX_TARGET` or your staging prefix), OpenSSL for QNX, or your own HSM ops (`-DUDS29_CRYPTO=CUSTOM`, register with `Uds29_SetCryptoOps`)

## Build

```sh
source ~/qnx/qnxsdp-env.sh
cmake -S . -B build-qnx \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/qnx-aarch64le.cmake \
  -DUDS29_CRYPTO=MBEDTLS -DUDS29_BUILD_HOST_TOOLS=OFF
cmake --build build-qnx -j
```

`UDS29_BUILD_HOST_TOOLS=OFF` skips the simulated ECU, CLI and GoogleTest (not meant for cross builds). The library
and, with `UDS29_ROLE=BOTH` and a built-in crypto backend, `doip_server_demo` / `doip_client_demo` are still built (the SocketCAN demos are Linux only).
Pick `-DUDS29_ROLE=CLIENT` or `SERVER` to build only one side.

## Install

```sh
cmake --install build-qnx --prefix $HOME/uds29-qnx     # lib + headers + uds29Config.cmake
```

Copy `doip_server_demo` / `doip_client_demo` to the target (for example with `scp`). If mbedTLS was fetched by CMake
instead of found, install rules are disabled (see README, Install).

## Use in your project

Same as Linux: `find_package(uds29)` with `CMAKE_PREFIX_PATH` pointing at the install prefix and the same toolchain
file, then `target_link_libraries(app PRIVATE uds29::uds29)`. The OS port is `UDS29_OS=POSIX` (default). Call
`Uds29Srv_HandleRequest` from your diagnostic stack (DoIP / ISO-TP resource manager), or use the client API as in
the [Linux guide](linux.md#use-in-your-project).

## Run

On the QNX target (two shells, or `&`):

```sh
./doip_server_demo --ca root_ca.pem --cert ecu_cert.pem --key ecu_key.pem &
./doip_client_demo --mode bi --ca root_ca.pem --cert tester_cert.pem --key tester_key.pem
```

Use your own PEM files on target: the `--pki sample` mode resolves to the source tree path baked in at build time
and will not exist on the target. Both programs speak DoIP (see [transports.md](transports.md)); QNX CAN needs its own frame driver for `isotp.c`.

## Confirm it works

Expected (identical to Linux, not verified on QNX):

```
[client] bidirectional authentication: AUTHENTICATED
[client] deauthentication: OK
PASS
```

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `QNX_HOST / QNX_TARGET not set` | source `qnxsdp-env.sh` in the same shell as `cmake` |
| `Could NOT find MbedTLS` | build/install mbedTLS 3.x for aarch64le and add it to `CMAKE_PREFIX_PATH` / `CMAKE_FIND_ROOT_PATH` |
| Link error `-lsocket` for the demos | QNX needs `-lsocket`; add `target_link_libraries(doip_*_demo PRIVATE socket)` when `CMAKE_SYSTEM_NAME` is `QNX` (not done in the repo: untested) |
| Other target CPU (x86_64, 8.0 triple) | copy the toolchain file and change `CMAKE_SYSTEM_PROCESSOR` and the `gcc_nto...` target |
| Tests / CLI fail to build | cross builds should use `-DUDS29_BUILD_HOST_TOOLS=OFF` |
