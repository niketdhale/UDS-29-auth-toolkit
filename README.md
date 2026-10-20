# UDS 0x29 Authentication Toolkit

Client-side implementation of ISO 14229-1:2020 SID 0x29 (Authentication) with certificate-based
unidirectional/bidirectional authentication, a transport callback so it runs over any bus, a
simulated ECU for loopback testing, fault injection, an interactive CLI and an optional bridge that
reports authentication failures to the [AUTOSAR IDSM toolkit](../autosar-idsm-toolkit).

## Features

- Tester API in AUTOSAR style (plain C11, `Std_ReturnType`, static memory, no heap): blocking calls and a non-blocking `StartAuthentication` / `MainFunction` / `RxIndication` flow on one state machine
- Sub-functions 0x00 deAuthenticate, 0x01 / 0x02 verifyCertificate (uni/bi), 0x03 proofOfOwnership
- Request/response codec for all sub-functions 0x00-0x08 (`Uds29_Codec_*`, plain C)
- PKI through a crypto port (`Uds29_Crypto.h`): OpenSSL (ECDSA P-256/SHA-256 or Ed25519) or mbedTLS 3.x (ECDSA P-256 only, no Ed25519) or your own HSM/PKCS#11 ops via `Uds29_SetCryptoOps`
- OS port (`Uds29_Os.h`): POSIX (Linux, QNX) or FreeRTOS; core is plain C11 with static buffers sized in `Uds29_Cfg.h`
- Sample PKI committed for demos, or your own PEM/DER files
- Transport callback: CAN-TP, DoIP, anything that can send bytes and return a response
- Simulated ECU with fault injection (expired cert, bad signature, challenge mismatch, wrong format, forced NRC)
- Exchange log (TX/RX bytes) and state/failure event callback
- Optional, customizable IDSM bridge
- Interactive CLI, also usable from piped stdin
- CMake package (`find_package(uds29)`), pkg-config file, static or shared library

## Architecture

```
 Application / Tester task
        |
   core        Uds29.h API  ->  Uds29_Manager.c (one state machine, codec, log, event callback) --> [optional] IDSM bridge
        |                              |                                |
   transport   blocking: Uds29_TransportFn      non-blocking: TX callback out, Uds29_RxIndication() in
               (CAN-TP, DoIP, ..., Uds29SimEcu)
        |
   crypto port  Uds29_Crypto.h   OpenSSL | mbedTLS 3.x | custom ops (Uds29_SetCryptoOps: HSM, PKCS#11, ...)
   OS port      Uds29_Os.h       POSIX (Linux, QNX) | FreeRTOS     (recursive lock + millisecond clock)
```

- **Core**: plain C11, static buffers sized in `Uds29_Cfg.h`, no heap, no exceptions. Every entry point takes the OS lock (recursive: callbacks may call back into the API).
- **Crypto port**: certificate/chain checks, signing, verifying, random. Pick one backend at build time.
- **OS port**: two functions plus a lock; ported to POSIX and FreeRTOS.
- **Transport**: not part of the library. Blocking API: you give a function that sends and returns the reply. Non-blocking API: you give a TX function and call `Uds29_RxIndication` when the reply arrives.

## Project Structure

```
include/   Uds29.h (API)  Uds29_Types.h  Uds29_Cfg.h  Uds29_Transport.h  Uds29_Codec.h  Uds29_Crypto.h  Uds29_Os.h
           (installed)    Uds29_Manager_Wrapper.h  Uds29_SimEcu.h  Uds29_SimEcu_C.h  Uds29_IdsM.h (not installed)
src/       Uds29.c  Uds29_Manager.c  Uds29_Codec.c  Uds29_Crypto.c  crypto/ (OpenSsl, MbedTls)  os/ (Posix, FreeRtos)
           Uds29_SimEcu.cpp (host test double)  Uds29_IdsM.c (optional)
apps/uds29_cli/main.cpp
examples/  linux_app.c  freertos_task.c  consumer/ (find_package demo)
cmake/     uds29Config.cmake.in  uds29.pc.in  toolchains/ (qnx-aarch64le, arm-none-eabi)
tests/     test_codec  test_pki  test_session  test_limits  test_async  test_idsm_bridge (only with IDSM)
certs/sample/  sample PKI + gen_sample_certs.sh
```

## API (`Uds29.h`)

| Function                                   | Purpose                                                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `Uds29_Init(cfg)` / `Uds29_DeInit()`       | Session config `{comm_config, challenge_len}`                                                 |
| `Uds29_SetTransport(fn, ctx)`              | Register the transport callback                                                               |
| `Uds29_SetPki(pki)`                        | Load client cert/key and root CA; `E_NOT_OK` on bad files, key/cert mismatch or invalid chain |
| `Uds29_SetEventCallback(cb)`               | State changes and failures (`Uds29_EventType`)                                                |
| `Uds29_AuthenticateUnidirectional()`       | 0x01 + 0x03                                                                                   |
| `Uds29_AuthenticateBidirectional()`        | 0x02 + 0x03, also verifies the ECU certificate and its proof of ownership                     |
| `Uds29_DeAuthenticate()`                   | 0x00                                                                                          |
| `Uds29_GetState()`                         | `IDLE, CERT_SENT, CHALLENGE_RECEIVED, POWN_SENT, AUTHENTICATED, FAILED`                       |
| `Uds29_SendRaw(req, len, resp, &resp_len)` | Send bytes as-is (logged, no state change)                                                    |
| `Uds29_GetLogCount/GetLogEntry/ClearLog`   | TX/RX exchange log                                                                            |

Also C: `Uds29_Codec_{Encode,Decode}{Request,Response}`, `Uds29_Codec_NrcToString`, `Uds29_Codec_ReturnParamToString`; the crypto port in `Uds29_Crypto.h`. The simulated ECU (`Uds29SimEcu`) is C++/STL, host-only, in the `uds29_sim` target.

## Non-blocking (AUTOSAR-style) API

The blocking calls above run the same state machine; they are refused (`E_NOT_OK`) while a non-blocking flow is in progress.

| Function                                  | Purpose                                                                                                                              |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `Uds29_SetTxCallback(fn, ctx)`            | `fn(req, len, ctx)` sends one request; return `E_OK` if sent (else the session FAILS). `req` is only valid during the call            |
| `Uds29_StartAuthentication(direction)`    | `UDS29_AUTH_UNIDIRECTIONAL` or `_BIDIRECTIONAL`. `E_MODE_INVALID` if not initialised / no PKI / no TX callback, `E_NOT_OK` if busy     |
| `Uds29_StartDeAuthentication()`           | Same for sub-function 0x00                                                                                                           |
| `Uds29_MainFunction()`                    | Call cyclically (e.g. every 10 ms). Sends the queued request via the TX callback; fails the session when a response is overdue       |
| `Uds29_RxIndication(resp, len)`           | Deliver the ECU response. `E_NOT_OK` if no request is pending (none sent yet, or already answered/timed out) or `len > UDS29_MAX_MSG_LEN`; the pending request is left untouched. Otherwise `E_OK`: NRCs and malformed responses are reported through `Uds29_GetState()` and the event callback, not the return value |
| `Uds29_GetState()`                        | `CERT_SENT` -> `CHALLENGE_RECEIVED` -> `POWN_SENT` -> `AUTHENTICATED` (or `IDLE` after a deauthentication), `FAILED` on error         |

Timeout: each request has `UDS29_P2_TIMEOUT_MS` (`Uds29_Cfg.h`, default 5000) from the moment `MainFunction` sent it; on expiry the state becomes `FAILED` and a failure event ("response timeout") is emitted. The TX callback may call `Uds29_RxIndication` synchronously (loopback). Resolution of the timeout is the `MainFunction` period.

```c
Uds29_Init(&cfg); Uds29_SetPki(&pki); Uds29_SetTxCallback(CanTx, &can);
Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL);
for (;;) { Uds29_MainFunction(); /* CAN rx path calls Uds29_RxIndication(); */ wait_10ms(); }
```

## PKI Modes

| Mode               | Behavior                                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UDS29_PKI_SAMPLE` | Uses `certs/sample/` (EC P-256, 10 years). Tester role for the client, ECU role for the simulated ECU. Private keys are committed on purpose: demos and tests only. |
| `UDS29_PKI_USER`   | `root_ca_path`, `cert_path`, `key_path`, `format` (PEM or DER, applies to all three).                                                                               |

Regenerate the sample PKI with `certs/sample/gen_sample_certs.sh`.

In the CLI, `pki load` makes the simulated ECU reuse the same cert/key as its own identity.

## Transport Adapter Example (blocking API)

```c
static Std_ReturnType MyTransport(const uint8_t* req, uint16_t len,
                                  uint8_t* resp, uint16_t* resp_len, void* ctx) {
    /* *resp_len = capacity on entry. Send req (incl. SID 0x29), block for the reply,
       copy it to resp, set *resp_len, return E_OK if a response arrived. */
    return MyDoip_Request((MyDoip*)ctx, req, len, resp, resp_len);
}

Uds29_ConfigType cfg = {0x00, 32};
Uds29_Init(&cfg);
Uds29_SetTransport(MyTransport, &doip);
Uds29_PkiConfigType pki = {UDS29_PKI_USER, "ca.pem", "tester.pem", "tester.key", UDS29_PKI_FORMAT_PEM};
Uds29_SetPki(&pki);
if (Uds29_AuthenticateBidirectional() != E_OK) { /* inspect the event callback / log */ }
```

For the simulator use `Uds29_SetTransport(Uds29SimEcu::Transport, &ecu)` after `ecu.Init(pki)`.

## Integration Guides

**Linux** (default `UDS29_OS=POSIX`, `UDS29_CRYPTO=OPENSSL`): link `uds29::uds29` (see Install). Run `Uds29_MainFunction()` from a loop/timer thread and call `Uds29_RxIndication()` from your SocketCAN/DoIP receive thread; both are thread-safe. `examples/linux_app.c` does exactly this against the simulated ECU and runs as a ctest.

**QNX** (SDP, aarch64): the POSIX OS port is used as is.
```
source ~/qnx/qnxsdp-env.sh
cmake -S . -B build-qnx -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/qnx-aarch64le.cmake -DUDS29_CRYPTO=MBEDTLS
```
The toolchain file (qcc, `QNX_HOST` / `QNX_TARGET`) has not been tested on a QNX system. Crypto: OpenSSL/mbedTLS for the QNX target, or `CUSTOM`.

**FreeRTOS** (`UDS29_OS=FREERTOS`, library only): enable `configUSE_RECURSIVE_MUTEXES` and `configSUPPORT_STATIC_ALLOCATION`, add your FreeRTOS include directories to target `uds29`, use `MBEDTLS` or `CUSTOM` crypto (arm-none-eabi: `-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi.cmake`, static library only).
```c
xTaskCreate(AuthTask, "uds29", 2048, NULL, prio, NULL);   /* stack in words: a session needs ~8 KB of stack */
/* AuthTask: Uds29_Init/SetPki/SetTxCallback, Uds29_StartAuthentication(), then loop:
     Uds29_MainFunction(); wait up to 10 ms for a queued CAN response; Uds29_RxIndication(...); */
```
`Uds29_Os_Lock` is not ISR-safe: the CAN ISR must queue the frame and a task calls `Uds29_RxIndication`. See `examples/freertos_task.c` (compiled by `UDS29_FREERTOS_COMPILE_CHECK`).

## Fault Injection (`Uds29SimEcu::SetFault`)

| Fault                | Effect                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------- |
| `EXPIRED_CERT`       | ECU judges the client cert at a later time: NRC 0x50                                        |
| `BAD_SIGNATURE`      | ECU corrupts its signature (0x02) / client POWN corrupted before the check (0x03): NRC 0x58 |
| `CHALLENGE_MISMATCH` | ECU signs/verifies against a different challenge                                            |
| `WRONG_CERT_FORMAT`  | 0x01: NRC 0x54; 0x02: ECU sends a garbage certificate                                       |
| `FORCE_NRC`          | Every request is answered with the given NRC                                                |

## IDSM Integration (optional)

Enable with `-DUDS29_ENABLE_IDSM=ON`. `IDSM_TOOLKIT_DIR` (default `../autosar-idsm-toolkit` next to
the source) is the checkout of the IDSM toolkit; only `IdsM.c`/`IdsM_Manager.cpp` are built (no IdsRm, no curl).

`Uds29_IdsM_Init(cfg)` registers a callback through `Uds29_SetEventCallback` that calls
`IdsM_ReportEvent`. The application still owns `IdsM_Init` (the monitor must exist and be enabled in
the current mode, otherwise the report is dropped silently) and the DEM callback.

| `Uds29_IdsM_ConfigType` field | Meaning                                                                |
| ----------------------------- | ---------------------------------------------------------------------- | ------------------------------ |
| `monitor_id`                  | IDSM monitor to report to (default 0x0290)                             |
| `success`                     | Entry for reaching `AUTHENTICATED` (default 0x29F0, LOW, **disabled**) |
| `failure_no_nrc`              | Failure detected by the client itself, no NRC (default 0x2900, HIGH)   |
| `nrc[256]`                    | Entry per NRC (default `0x2900                                         | nrc`, HIGH; NRC 0x58 CRITICAL) |
| `include_payload`             | Payload `{nrc, sub_function, state}` (default on)                      |

Each entry is `{event_id, severity, enabled}`.

```c
Uds29_IdsM_ConfigType c;
Uds29_IdsM_GetDefaultConfig(&c);
c.monitor_id = 0x0042;
c.success = (Uds29_IdsM_MapEntry){0x3000, IDSM_SEVERITY_LOW, true};
c.nrc[UDS29_NRC_CVF_INVALID_TIME_PERIOD].enabled = false;
c.nrc[UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST].severity = IDSM_SEVERITY_CRITICAL;

IdsM_MonitorConfigType m = {0x0042, 32, 0, IDSM_SEVERITY_LOW, false, true, false};
IdsM_Init(&m, 1);
IdsM_SetOperatingMode(IDSM_RUN_MODE);
Uds29_IdsM_Init(&c);
```

The bridge replaces any other event callback; to keep your own, call `Uds29_IdsM_OnEvent(e)` from it.

## Build Options

| Option (CMake cache variable)       | Default   | Meaning                                                                                                                      |
| ----------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `UDS29_CRYPTO`                      | `OPENSSL` | `OPENSSL`, `MBEDTLS` (`find_package(MbedTLS 3)`, else v3.6.2 is fetched) or `CUSTOM` (register ops with `Uds29_SetCryptoOps`; core library only) |
| `UDS29_OS`                          | `POSIX`   | `POSIX` (Linux, QNX) or `FREERTOS` (core library only)                                                                        |
| `UDS29_ENABLE_IDSM`                 | `OFF`     | Build the IDSM bridge; `IDSM_TOOLKIT_DIR` points at the IDSM toolkit checkout                                                |
| `UDS29_FREERTOS_COMPILE_CHECK`      | `OFF`     | Fetch FreeRTOS-Kernel V11.1.0 and compile the FreeRTOS OS port and `examples/freertos_task.c` against it (no link, no run)  |
| `BUILD_SHARED_LIBS`                 | `OFF`     | Build `libuds29` as a shared library                                                                                          |
| `UDS29_MAX_CERT_LEN` / `_CHALLENGE_LEN` / `_SIG_LEN` / `_MAX_MSG_LEN` / `UDS29_LOG_DEPTH` | 1024 / 64 / 128 / 1300 / 32 | Static buffer sizes (also settable with `-D` for non-CMake builds; all translation units must agree) |
| `UDS29_P2_TIMEOUT_MS`               | 5000      | Non-blocking API: per-response timeout (`-D` / `Uds29_Cfg.h`)                                                                |

```
cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
cmake -S . -B build-idsm -DUDS29_ENABLE_IDSM=ON -DIDSM_TOOLKIT_DIR=/path/to/autosar-idsm-toolkit
cmake --build build-idsm -j && ctest --test-dir build-idsm
```
Requires CMake 3.16+, a C11/C++17 compiler, OpenSSL dev files (default backend); GoogleTest is fetched. Host tools (sim ECU, CLI, tests, `examples/linux_app.c`) are built for `POSIX` with `OPENSSL` or `MBEDTLS`. Linux only: there is no Windows build.

## Install and `find_package`

```
cmake --install build --prefix /opt/uds29
```
installs `libuds29` (static, or shared with `BUILD_SHARED_LIBS=ON`), the public headers (`Uds29.h`, `_Types`, `_Cfg`, `_Transport`, `_Codec`, `_Crypto`, `_Os`), `uds29_cli`, `uds29Config.cmake` and `uds29.pc`.
Size macros set at configure time are recorded in the exported target, so consumers see the same values.
```cmake
find_package(uds29 REQUIRED)            # -DCMAKE_PREFIX_PATH=/opt/uds29
target_link_libraries(app PRIVATE uds29::uds29)
```
`examples/consumer/` is a minimal project doing exactly this. pkg-config: `pkg-config --cflags --libs uds29` (add `--static` for a static library). With `UDS29_CRYPTO=MBEDTLS` and no system mbedTLS (fetched), install rules are disabled because the fetched targets cannot be exported.

## Memory Footprint

Static RAM of the core (x86-64 build, defaults): about 44 KB `.bss`, of which 41.7 KB is the exchange log (`UDS29_LOG_DEPTH` x (`UDS29_MAX_MSG_LEN` + 4)); the rest is the session state, the TX buffer (1300), the own certificate (1024) and the challenge. Shrink `UDS29_LOG_DEPTH` first on small targets (e.g. 4 -> about 8 KB total). The OS port adds a mutex. Code size depends on the backend and compiler; it was not measured on a microcontroller.

## CLI

`./build/uds29_cli` (reads commands from stdin, so it also works piped):

| Command                                                       |                                                                 |
| ------------------------------------------------------------- | --------------------------------------------------------------- |
| `pki sample` / `pki load <ca> <cert> <key> [der]`             | Load PKI (required before `auth`)                               |
| `auth uni` / `auth bi`, `deauth`                              | Run a flow                                                      |
| `send <hex>`, `decode <hex>`                                  | Raw request via the ECU / decode a request or response          |
| `inject none\|expired\|badsig\|mismatch\|wrongfmt\|nrc <hex>` | Simulated ECU fault                                             |
| `status`, `log`, `clear`, `help`, `quit`                      |                                                                 |
| `idsm status`                                                 | Only when built with IDSM: pending/forwarded counts, last event |

```
$ printf 'pki sample\nauth uni\ninject badsig\nauth uni\nstatus\nquit\n' | ./build/uds29_cli
[PKI] loaded
[AUTH] uni -> OK (state AUTHENTICATED)
[SIM] fault = badsig
  [event] FAILURE sub=0x03 nrc=0x58 ownershipVerificationFailed
[AUTH] uni -> FAILED (state FAILED)
[STATUS] state=FAILED pki=loaded fault=badsig log=...
```

## Limitations

- Fixed buffers: certificates up to `UDS29_MAX_CERT_LEN` (1024), challenges `UDS29_MAX_CHALLENGE_LEN` (64), signatures `UDS29_MAX_SIG_LEN` (128), messages `UDS29_MAX_MSG_LEN` (1300). Larger input is refused (`E_NOT_OK`, or NRC 0x13 from the simulated ECU). The exchange log keeps the last `UDS29_LOG_DEPTH` (32) entries.
- One session per process: all state is global (one client, one ECU). One request in flight; the non-blocking and blocking flows cannot run at the same time.
- Non-blocking timeout granularity is the `MainFunction` period; `Uds29_Os_GetTimeMs` wraps after ~49 days (handled by unsigned subtraction). A stray or oversize `RxIndication` is rejected, not treated as a failure. No retry.
- The FreeRTOS port and example are only compile-checked against the kernel headers (posix port); they were not run on a target. The QNX and arm-none-eabi toolchain files are untested here.
- Ed25519 PKI is OpenSSL-only; the mbedTLS backend returns `E_NOT_OK`.
- Client side only; the simulated ECU is a test double (sub-functions 0x00-0x03 and 0x08 only).
- The proof-of-ownership signature covers the raw challenge only, not the full ISO 14229 data structure.
- The ephemeral public key field is sent empty; no session key is derived.
- Sub-functions 0x04-0x07 are encoded/decoded but there is no client flow for them.
- The IDSM bridge is fire-and-forget: it ignores `IdsM_ReportEvent` errors; IDSM forwards to DEM asynchronously.
