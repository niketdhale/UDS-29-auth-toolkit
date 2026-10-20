# UDS 0x29 Authentication Toolkit

Client-side implementation of ISO 14229-1:2020 SID 0x29 (Authentication) with certificate-based
unidirectional/bidirectional authentication, a transport callback so it runs over any bus, a
simulated ECU for loopback testing, fault injection, an interactive CLI and an optional bridge that
reports authentication failures to the [AUTOSAR IDSM toolkit](../autosar-idsm-toolkit).

## Features

- Tester API in AUTOSAR style (C, `Std_ReturnType`) over a C++ session manager
- Sub-functions 0x00 deAuthenticate, 0x01 / 0x02 verifyCertificate (uni/bi), 0x03 proofOfOwnership
- Request/response codec for all sub-functions 0x00-0x08 (`Uds29Codec`)
- PKI on OpenSSL libcrypto: chain + validity check, ECDSA P-256/SHA-256 or Ed25519 signatures
- Sample PKI committed for demos, or your own PEM/DER files
- Transport callback: CAN-TP, DoIP, anything that can send bytes and return a response
- Simulated ECU with fault injection (expired cert, bad signature, challenge mismatch, wrong format, forced NRC)
- Exchange log (TX/RX bytes) and state/failure event callback
- Optional, customizable IDSM bridge
- Interactive CLI, also usable from piped stdin

## Architecture

```
 Application / Tester
        |
   Uds29_* API (Uds29.h)
        |
   Uds29_Manager  -- state machine, codec, PKI, log -----> event callback --+
        |                                                                    |
   Transport callback (Uds29_TransportFn)                      [optional] Uds29_IdsM bridge
        |                                                                    |
  CAN-TP / DoIP / ... / Uds29SimEcu (loopback)                      IdsM_ReportEvent -> IDSM
```

## Project Structure

```
include/  Uds29.h (API)  Uds29_Types.h  Uds29_Transport.h  Uds29_Codec.h  Uds29_Pki.h
          Uds29_Manager.h  Uds29_Manager_Wrapper.h  Uds29_SimEcu.h  Uds29_IdsM.h (optional)
src/      Uds29.c  Uds29_Manager.cpp  Uds29_Codec.cpp  Uds29_Pki.cpp  Uds29_SimEcu.cpp  Uds29_IdsM.cpp (optional)
apps/uds29_cli/main.cpp
tests/    test_codec  test_pki  test_session  test_idsm_bridge (only with IDSM)
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

C++ extras: `Uds29Codec::{Encode,Decode}{Request,Response}`, `NrcToString`, `ReturnParamToString`; `Uds29Pki`.

## PKI Modes

| Mode               | Behavior                                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UDS29_PKI_SAMPLE` | Uses `certs/sample/` (EC P-256, 10 years). Tester role for the client, ECU role for the simulated ECU. Private keys are committed on purpose: demos and tests only. |
| `UDS29_PKI_USER`   | `root_ca_path`, `cert_path`, `key_path`, `format` (PEM or DER, applies to all three).                                                                               |

Regenerate the sample PKI with `certs/sample/gen_sample_certs.sh`.

In the CLI, `pki load` makes the simulated ECU reuse the same cert/key as its own identity.

## Transport Adapter Example

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

## Build & Test

Requires CMake 3.16+, a C11/C++17 compiler, OpenSSL dev files; GoogleTest is fetched.

```
cmake -S . -B build && cmake --build build -j && ctest --test-dir build
cmake -S . -B build-idsm -DUDS29_ENABLE_IDSM=ON -DIDSM_TOOLKIT_DIR=/path/to/autosar-idsm-toolkit
cmake --build build-idsm -j && ctest --test-dir build-idsm
```

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

- Client side only; the simulated ECU is a test double (sub-functions 0x00-0x03 and 0x08 only).
- The proof-of-ownership signature covers the raw challenge only, not the full ISO 14229 data structure.
- The ephemeral public key field is sent empty; no session key is derived.
- Sub-functions 0x04-0x07 are encoded/decoded but there is no client flow for them.
- The IDSM bridge is fire-and-forget: it ignores `IdsM_ReportEvent` errors; IDSM forwards to DEM asynchronously.
