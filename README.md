# UDS 0x29 Authentication Toolkit

[![CI](https://github.com/niketdhale/UDS-29-auth-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/niketdhale/UDS-29-auth-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![C11](https://img.shields.io/badge/C-11-blue.svg)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![ISO 14229-1:2020](https://img.shields.io/badge/ISO-14229--1%3A2020-informational.svg)
![AUTOSAR-style](https://img.shields.io/badge/API-AUTOSAR--style-informational.svg)
![CMake 3.16+](https://img.shields.io/badge/CMake-3.16%2B-064F8C.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20QNX%20%7C%20FreeRTOS-lightgrey.svg)

A small, embeddable implementation of ISO 14229-1:2020 service 0x29 (Authentication) with certificate-based
unidirectional and bidirectional authentication, for both ends of the link: a **client** (tester) and a **server** (ECU).
Plain C11, static memory, no heap, pluggable crypto (OpenSSL, mbedTLS or your HSM) and OS port (POSIX or FreeRTOS),
bring-your-own transport (demos for DoIP and CAN ISO-TP). Includes certificate-based access control with an OEM-definable
certificate format, a simulated ECU with fault injection, an interactive CLI, two-process DoIP and CAN demos, and an optional bridge that reports authentication failures to the
[AUTOSAR IDSM toolkit](../autosar-idsm-toolkit).

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Client vs server](#client-vs-server)
- [Access control](#access-control)
- [Certificate validation](#certificate-validation)
- [Sub-function support](#sub-function-support)
- [Build options](#build-options)
- [Documentation](#documentation)
- [CLI](#cli)
- [IDSM integration](#idsm-integration)
- [Memory footprint](#memory-footprint)
- [Limitations](#limitations)
- [License](#license)

## Quick start

```sh
sudo apt-get install -y libssl-dev cmake g++          # once
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure            # unit tests + two-process DoIP demo
./build/doip_server_demo & sleep 1; ./build/doip_client_demo --mode bi            # prints PASS
printf 'pki sample\nauth bi\nquit\n' | ./build/uds29_cli                          # simulated ECU
```

## Features

**Client**
- Tester API in AUTOSAR style (`Std_ReturnType`): blocking calls and a non-blocking `StartAuthentication` / `MainFunction` / `RxIndication` flow on one state machine
- Sub-functions 0x00 deAuthenticate, 0x01 / 0x02 verifyCertificate (uni/bi), 0x03 proofOfOwnership; bidirectional also verifies the ECU certificate and its signature
- TX/RX exchange log, state and failure event callback, P2 timeout for the non-blocking flow

**Server**
- ECU side, DCM-style: `Uds29Srv_HandleRequest(req, len, resp, &resp_len)` takes a full request and writes the positive or `7F 29 nrc` response
- 0x00, 0x01, 0x02, 0x03, 0x08; NRC 0x12 / 0x13 / 0x24 / 0x50-0x58 as the standard prescribes
- Random challenge, certificate chain and validity check, authentication timeout
- Opt-in certificate hardening: intermediate CAs, CRL and serial blacklist, key usage / EKU / algorithm policy, trusted-time hook, configurable proof-of-ownership data ([docs/certificate-validation.md](docs/certificate-validation.md))
- Access control from the client certificate: roles and service / DID / routine allow-lists in an OEM-defined format (extension OID, subject OU or CN, or your own parser), enforced against an ECU rule table with NRC 0x34 ([docs/access-control.md](docs/access-control.md))

**Crypto**
- Crypto port (`Uds29_Crypto.h`): OpenSSL (ECDSA P-256 or Ed25519), mbedTLS 3.x (ECDSA P-256 only), or your own HSM / PKCS#11 ops via `Uds29_SetCryptoOps`
- Sample PKI committed for demos, or your own PEM/DER files

**OS**
- OS port (`Uds29_Os.h`): POSIX (Linux, QNX) or FreeRTOS; two functions plus a recursive lock
- Static buffers sized in `Uds29_Cfg.h`; thread-safe

**Integration**
- Transport is yours: one callback (blocking) or TX callback + `Uds29_RxIndication` (non-blocking); the server just consumes bytes
- Optional IDSM bridge for client and server events
- CMake package (`find_package(uds29)`), pkg-config, static or shared library, `UDS29_ROLE=CLIENT|SERVER|BOTH`

**Tooling**
- Simulated ECU (`Uds29SimEcu`, a thin wrapper over the server) with fault injection: expired cert, bad signature, challenge mismatch, wrong format, forced NRC
- `uds29_cli`: interactive tester, or `--role server` for hex in / hex out
- Two-process demos over DoIP (`doip_server_demo`, `doip_client_demo`) and CAN ISO-TP on SocketCAN (`can_server_demo`, `can_client_demo`, with a userspace ISO-TP), `access_control_demo`, GoogleTest suites, CI matrix
- `uds29_cli cert inspect <file>` prints a certificate's subject, validity, serial, key type, signature algorithm, keyUsage, EKU, decoded roles / allow-lists and the chain result against the loaded PKI (`pki load ... [--inter f] [--crl f]`)

## Architecture

```text
 Tester application                          ECU diagnostic stack (DCM)
        │ Uds29_* API                                    ▲
        ▼                                                │ Uds29Srv_HandleRequest()
 ┌──────────────────────┐                    ┌───────────┴──────────┐
 │ Client               │   request bytes    │ Server               │
 │ (Uds29.h)            │ ──── CAN ISO-TP ─▶ │ (Uds29_Server.h)     │
 │ state machine,       │ ──── DoIP ───────▶ │ state machine, role, │
 │ log, events          │ ◀─── response ──── │ timeout, access ctrl │
 └──────────┬───────────┘                    └───────────┬──────────┘
            └──────────────────┬─────────────────────────┘
                               ▼ shared by both
              ┌────────────────────────────────┐
              │ Codec        Uds29_Codec.h     │
              │ Crypto port  Uds29_Crypto.h  ──┼──▶ OpenSSL │ mbedTLS │ HSM / custom
              │ OS port      Uds29_Os.h      ──┼──▶ POSIX (Linux, QNX) │ FreeRTOS
              └────────────────────────────────┘

 optional:  client / server events ┄┄▶ IDSM bridge ┄┄▶ IdsM_ReportEvent()
```

The transport is not part of the library. Blocking client: you give a function that sends and returns the reply.
Non-blocking client: you give a TX function and call `Uds29_RxIndication` when the reply arrives. Server: you call
`Uds29Srv_HandleRequest` for every received request and transmit the response it wrote.

## Client vs server

| | Client (tester) | Server (ECU) |
| --- | --- | --- |
| Header / prefix | `Uds29.h` / `Uds29_` | `Uds29_Server.h` / `Uds29Srv_` |
| Role | starts authentication, proves ownership of its key | verifies the client, issues the challenge, optionally proves its own identity (bidirectional) |
| Drives | `Uds29_AuthenticateUnidirectional/Bidirectional`, `Uds29_DeAuthenticate` | `Uds29Srv_HandleRequest`, `Uds29Srv_MainFunction` |
| Static RAM | about 44 KB (log dominated) | about 5.3 KB |

Select with `-DUDS29_ROLE=CLIENT|SERVER|BOTH` (default `BOTH`; host tools, demos and most tests need `BOTH`).
Sequence diagrams, state description, and both API tables: [docs/client-server.md](docs/client-server.md).

## Access control

The certificate carries *roles* (a bit mask) and optional allow-lists of services, DIDs and routines. Where and how is
**configuration**, not code: an OEM fills a `Uds29_CertProfile` (extension OID, subject OU or CN; BIT STRING, INTEGER mask,
OCTET STRING of 8/16/32-bit ids, SEQUENCE OF INTEGER, or a string table), or registers its own parser. The ECU holds a rule
table ("service 0x2E on DID F190 needs engineering or oem") and calls `Uds29Srv_CheckAccess()` before running a service.

```c
cfg.profile = &kProfile;                                   /* how to read roles / allow-lists from the certificate */
Uds29Srv_Init(&cfg);
Uds29Srv_SetAccessRules(kRules, n);                        /* { sid, sub-function / DID / RID or UDS29_ANY, roles } */
...
uint8_t nrc;
if (Uds29Srv_CheckAccess(req, len, &nrc) != E_OK) { /* answer 7F req[0] nrc, 0x34 by default */ }
```

`examples/access_control_demo` (ctest) shows it with four sample certificates: a workshop tester reads `22 F1 90`, is refused
`2E F1 90 ..` and `34 ..` with `7F 2E 34` / `7F 34 34`, the OEM tester may do everything, and a certificate with an allow-list is
narrowed to services 22 and 3E and two DIDs. Full guide, with a worked OEM format and the `openssl` extension config:
[docs/access-control.md](docs/access-control.md). The OID arc used by the samples (`1.3.6.1.4.1.99999.29.x`) is an example, not a registered number.

## Certificate validation

The peer certificate (the tester's on the server, the ECU's on the client) passes one pipeline. The defaults are the 0.4
behaviour (chain + validity at the system time); everything else is opt-in:

| Check | Config | Server NRC |
| --- | --- | --- |
| Parse / chain to the root (CA constraints, pathLen) | `root_ca_path` | 0x54 / 0x52 |
| Through intermediate CAs (leaf-only peers) | `intermediate_paths[]` (`UDS29_MAX_INTERMEDIATES`) | 0x52 (0x51 bad signature, OpenSSL only) |
| Validity period | `policy.time_mode` SYSTEM / HOOK / SKIP_WITH_EVENT | 0x50 |
| Trusted time, never goes back | `Uds29(Srv)_SetTimeSource`, `time_monotonic_guard` | 0x50 |
| CRL (incl. `nextUpdate`) | `crl_paths[]` | 0x57 |
| Serial blacklist | `Uds29(Srv)_SetRevokedSerials` | 0x57 |
| keyUsage digitalSignature, EKU | `policy.require_key_usage_digital_signature`, `required_eku_oid` | 0x53 |
| Key type, signature algorithm | `policy.allowed_key_types`, `allowed_sig_algs` | 0x53 |
| Proof-of-ownership data | `pown` (raw challenge, or server/client challenge, additional parameter, certificate hashes) | 0x58 |

**NRCs changed in 0.6.0** (revoked 0x52 -> 0x57, key usage / EKU / algorithm 0x56 -> 0x53, bad signature 0x52 -> 0x51 on OpenSSL); `Uds29Srv_ConfigType.nrc_collapse = true` restores the 0.5.0 values. Also new: `supported_comm_config_mask` (0x5C) and an opt-in lockout (`max_failed_attempts`, `lockout_delay_ms`: 0x36 / 0x37). Full NRC table (0x34 / 0x36 / 0x37 / 0x50-0x5D) in the document below.

Table of every check, NRC reasoning, recommended production profile and limits (no OCSP):
[docs/certificate-validation.md](docs/certificate-validation.md). The server and client configs gained trailing fields
(`policy`, `pown`; the PKI config `intermediate_paths`, `crl_paths`): initialise with `{0}` / `{}` / designated initialisers
to avoid `-Wmissing-field-initializers`.

## Sub-function support

| Sub-function | Client flow | Server | Codec |
| --- | --- | --- | --- |
| 0x00 deAuthenticate | yes | yes | yes |
| 0x01 verifyCertificateUnidirectional | yes | yes | yes |
| 0x02 verifyCertificateBidirectional | yes | yes | yes |
| 0x03 proofOfOwnership | yes | yes | yes |
| 0x04 transmitCertificate | no | NRC 0x12 | yes |
| 0x05 requestChallengeForAuthentication | no | NRC 0x12 | yes |
| 0x06 verifyProofOfOwnershipUnidirectional | no | NRC 0x12 | yes |
| 0x07 verifyProofOfOwnershipBidirectional | no | NRC 0x12 | yes |
| 0x08 authenticationConfiguration | no | yes (APCE) | yes |

The codec encodes and decodes all of them (`Uds29_Codec_*`), so you can build the missing flows on top with `Uds29_SendRaw`.

## Build options

| Option (CMake cache variable) | Default | Meaning |
| --- | --- | --- |
| `UDS29_ROLE` | `BOTH` | `CLIENT`, `SERVER` or `BOTH`: which sources go into `libuds29` and which headers install |
| `UDS29_CRYPTO` | `OPENSSL` | `OPENSSL`, `MBEDTLS` (`find_package(MbedTLS 3)`, else v3.6.2 is fetched) or `CUSTOM` (register ops with `Uds29_SetCryptoOps`; core library only) |
| `UDS29_OS` | `POSIX` | `POSIX` (Linux, QNX) or `FREERTOS` (core library only) |
| `UDS29_BUILD_HOST_TOOLS` | `ON` | Sim ECU, CLI, `linux_app`, ctest suites, GoogleTest. Turn `OFF` when cross-compiling |
| `UDS29_ENABLE_IDSM` | `OFF` | Build the IDSM bridge; `IDSM_TOOLKIT_DIR` points at the IDSM toolkit checkout |
| `UDS29_FREERTOS_COMPILE_CHECK` | `OFF` | Fetch FreeRTOS-Kernel V11.1.0 and compile the FreeRTOS OS port and `examples/freertos_task.c` against it (no link, no run) |
| `BUILD_SHARED_LIBS` | `OFF` | Build `libuds29` as a shared library |
| `UDS29_MAX_CERT_LEN` / `_CHALLENGE_LEN` / `_SIG_LEN` / `_MAX_MSG_LEN` / `UDS29_LOG_DEPTH` / `UDS29_MAX_ALLOW` / `UDS29_MAX_INTERMEDIATES` | 1024 / 64 / 128 / 1300 / 32 / 32 / 2 | Static buffer sizes and the length of each certificate allow-list (also settable with `-D` for non-CMake builds; all translation units must agree); intermediate CAs per PKI config |
| `UDS29_P2_TIMEOUT_MS` | 5000 | Client non-blocking API: per-response timeout (`-D` / `Uds29_Cfg.h`) |

Requires CMake 3.16+, a C11/C++17 compiler, OpenSSL dev files (default backend); GoogleTest is fetched. There is no
Windows build.

## Documentation

| Guide | Contents |
| --- | --- |
| [docs/linux.md](docs/linux.md) | build, install, `find_package`, run client / server / DoIP demo, troubleshooting (tested) |
| [docs/transports.md](docs/transports.md) | plugging in a transport; DoIP (ISO 13400-2) and CAN ISO-TP (ISO 15765-2) demos, `vcan` setup, own adapters |
| [docs/access-control.md](docs/access-control.md) | roles and allow-lists in certificates, defining an OEM certificate format, access rules, NRC 0x34, CLI, demo |
| [docs/certificate-validation.md](docs/certificate-validation.md) | every certificate check with config and NRC, intermediates, CRL / blacklist, EKU and algorithm policy, trusted time, proof-of-ownership data, production profile, limits |
| [docs/qnx.md](docs/qnx.md) | QNX SDP cross build (untested: no SDK here) |
| [docs/freertos.md](docs/freertos.md) | FreeRTOS integration (compile-checked only, not run on a target) |
| [docs/client-server.md](docs/client-server.md) | roles, sequence diagrams, `UDS29_ROLE`, API tables |

Install in one line: `cmake --install build --prefix /opt/uds29`, then `find_package(uds29 REQUIRED)` and
`target_link_libraries(app PRIVATE uds29::uds29)` (`examples/consumer/` is a minimal project; pkg-config: `pkg-config --cflags --libs uds29`).

<details>
<summary>Project structure</summary>

```
include/   Uds29.h (client API)  Uds29_Server.h (server API)  Uds29_Types.h  Uds29_Cfg.h  Uds29_Transport.h  Uds29_Codec.h
           Uds29_Crypto.h  Uds29_Os.h  Uds29_Authz.h              (installed according to UDS29_ROLE)
           Uds29_Manager_Wrapper.h  Uds29_ServerTest.h  Uds29_SimEcu.h  Uds29_SimEcu_C.h  Uds29_IdsM.h   (not installed)
src/       Uds29.c  Uds29_Manager.c (client)  Uds29_Server.c  Uds29_Authz.c  Uds29_Der.h  Uds29_Policy.c/.h  Uds29_Codec.c  Uds29_Crypto.c  crypto/ (OpenSsl, MbedTls)
           os/ (Posix, FreeRtos)  Uds29_SimEcu.cpp (host test double)  Uds29_IdsM.c (optional)
apps/uds29_cli/main.cpp
examples/  linux_app.c  access_control_demo.c  access_example.h  freertos_task.c  consumer/ (find_package demo)
           transports/ (doip, isotp, can_socketcan, can_loopback, doip_*_demo.c, can_*_demo.c)
docs/      linux.md  qnx.md  freertos.md  client-server.md  transports.md  access-control.md
cmake/     uds29Config.cmake.in  uds29.pc.in  toolchains/ (qnx-aarch64le, arm-none-eabi)
tests/     test_codec  test_pki  test_session  test_limits  test_async  test_server  test_authz  test_isotp  test_validation  test_idsm_bridge (IDSM only)  run_doip_demo.sh  run_can_demo.sh
certs/sample/  sample PKI (root, sub-CA, testers, CRLs) + gen_sample_certs.sh + oem_profile.cnf (example roles / allow-list / EKU extensions)
```
</details>

<details>
<summary>PKI modes and sample certificates</summary>

| Mode | Behavior |
| --- | --- |
| `UDS29_PKI_SAMPLE` | Uses `certs/sample/` (EC P-256, 10 years). Tester role for the client, ECU role for the server / simulated ECU. Private keys are committed on purpose: demos and tests only. Works from the build tree only. |
| `UDS29_PKI_USER` | `root_ca_path`, `cert_path`, `key_path`, `format` (PEM or DER, applies to all three). |

Regenerate the sample PKI with `certs/sample/gen_sample_certs.sh`. In the CLI, `pki load` makes the simulated ECU reuse the same cert/key as its own identity.
</details>

<details>
<summary>Client API (blocking and non-blocking)</summary>

| Function | Purpose |
| --- | --- |
| `Uds29_Init(cfg)` / `Uds29_DeInit()` | Session config `{comm_config, challenge_len}` |
| `Uds29_SetTransport(fn, ctx)` | Register the transport callback |
| `Uds29_SetPki(pki)` | Load client cert/key and root CA; `E_NOT_OK` on bad files, key/cert mismatch or invalid chain |
| `Uds29_SetEventCallback(cb)` | State changes and failures (`Uds29_EventType`) |
| `Uds29_AuthenticateUnidirectional()` | 0x01 + 0x03 |
| `Uds29_AuthenticateBidirectional()` | 0x02 + 0x03, also verifies the ECU certificate and its proof of ownership |
| `Uds29_DeAuthenticate()` | 0x00 |
| `Uds29_GetState()` | `IDLE, CERT_SENT, CHALLENGE_RECEIVED, POWN_SENT, AUTHENTICATED, FAILED` |
| `Uds29_SendRaw(req, len, resp, &resp_len)` | Send bytes as-is (logged, no state change) |
| `Uds29_GetLogCount/GetLogEntry/ClearLog` | TX/RX exchange log |

**Non-blocking (AUTOSAR-style) flow**

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

</details>

<details>
<summary>Transport adapter example (blocking client)</summary>

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

For the simulator use `Uds29_SetTransport(Uds29SimEcu::Transport, &ecu)` after `ecu.Init(pki)`. Complete transports are `examples/transports/doip_client_demo.c` and `can_client_demo.c` (see [docs/transports.md](docs/transports.md)).
</details>

<details>
<summary>Fault injection (<code>Uds29SimEcu::SetFault</code>, <code>Uds29Srv_SetFaultForTest</code>)</summary>

| Fault | Effect |
| --- | --- |
| `EXPIRED_CERT` | ECU judges the client cert at a later time: NRC 0x50 |
| `BAD_SIGNATURE` | ECU corrupts its signature (0x02) / client POWN corrupted before the check (0x03): NRC 0x58 |
| `CHALLENGE_MISMATCH` | ECU signs/verifies against a different challenge |
| `WRONG_CERT_FORMAT` | 0x01: NRC 0x54; 0x02: ECU sends a garbage certificate |
| `FORCE_NRC` | Every well-formed request is answered with the given NRC |

The hooks live in `include/Uds29_ServerTest.h` (not installed) and are meant for tests only.
</details>

## CLI

`./build/uds29_cli [--role client|server]` (reads stdin, so it also works piped).

**Client (default)**: interactive tester against the simulated ECU.

| Command                                                       |                                                                 |
| ------------------------------------------------------------- | --------------------------------------------------------------- |
| `pki sample` / `pki load <ca> <cert> <key> [der] [--inter f]... [--crl f]...` | Load PKI (required before `auth`), optional intermediates / CRLs |
| `auth uni` / `auth bi`, `deauth`                              | Run a flow                                                      |
| `send <hex>`, `decode <hex>`                                  | Raw request via the ECU / decode a request or response          |
| `inject none\|expired\|badsig\|mismatch\|wrongfmt\|nrc <hex>` | Simulated ECU fault                                             |
| `status`, `log`, `clear`, `help`, `quit`                      |                                                                 |
| `cert inspect <file> [der]`                                   | Subject, issuer, validity, serial, key, signature algorithm, keyUsage, EKU, roles / allow-lists (example profile) and the chain result (incl. CRL) against the loaded PKI |
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


**Server** (`--role server`, optional `--ca F --cert F --key F`, else the sample ECU PKI): one hex request per line on stdin, one hex response per line on stdout.

```
$ printf '29 08\n29 04\n' | ./build/uds29_cli --role server
69 08 02
7F 29 12
```

In server mode the example access rules are active: `access <hex>` checks a request, `login <cert> <key>` / `logout` / `authz` authenticate a sample tester in-process ([docs/access-control.md](docs/access-control.md)).

The two-process DoIP demo (`doip_server_demo`, `doip_client_demo --mode uni|bi`, both accepting `--pki sample | --ca --cert --key`) prints `PASS` or `FAIL`; the CAN ISO-TP pair is `can_server_demo` / `can_client_demo`; see [docs/transports.md](docs/transports.md).

## IDSM Integration

Enable with `-DUDS29_ENABLE_IDSM=ON`. `IDSM_TOOLKIT_DIR` (default `../autosar-idsm-toolkit` next to
the source) is the checkout of the IDSM toolkit; only `IdsM.c`/`IdsM_Manager.cpp` are built (no IdsRm, no curl).

`Uds29_IdsM_Init(cfg)` registers a callback through `Uds29_SetEventCallback` (client) that calls
`IdsM_ReportEvent`. The application still owns `IdsM_Init` (the monitor must exist and be enabled in
the current mode, otherwise the report is dropped silently) and the DEM callback.

| `Uds29_IdsM_ConfigType` field | Meaning                                                                |
| ----------------------------- | ---------------------------------------------------------------------- |
| `monitor_id`                  | IDSM monitor to report to (default 0x0290)                             |
| `success`                     | Entry for reaching `AUTHENTICATED` (default 0x29F0, LOW, **disabled**) |
| `failure_no_nrc`              | Failure detected by the client itself, no NRC (default 0x2900, HIGH)   |
| `nrc[256]`                    | Entry per NRC (default `0x2900 \| nrc`, HIGH; NRC 0x58 CRITICAL)        |
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

Server role: `Uds29_IdsM_InitServer(&c)` attaches the same mapping to `Uds29Srv_SetEventCallback`; the "failures" are then the NRCs the ECU sent (and auth timeouts, which use `failure_no_nrc`). Client and server bridges share one config.

The bridge replaces any other event callback on the side it is attached to; to keep your own, call `Uds29_IdsM_OnEvent(e)` from it.

## Memory footprint

Static RAM (x86-64 build, defaults, `.bss`):

| Role | RAM | Notes |
| --- | --- | --- |
| Client | about 44 KB | 41.7 KB is the exchange log (`UDS29_LOG_DEPTH` x (`UDS29_MAX_MSG_LEN` + 4)); the rest is session state, the TX buffer (1300), the own certificate (1024) and the challenge. `UDS29_LOG_DEPTH` 4 gives about 8 KB total |
| Server | about 5.5 KB | own and client certificate (2 x 1024), request / response scratch, challenge, the client's `Uds29_Authz` (about 170 bytes) |

The OS port adds a mutex. Code size depends on the backend and compiler; it was not measured on a microcontroller.

## Limitations

- Fixed buffers: certificates up to `UDS29_MAX_CERT_LEN` (1024), challenges `UDS29_MAX_CHALLENGE_LEN` (64), signatures `UDS29_MAX_SIG_LEN` (128), messages `UDS29_MAX_MSG_LEN` (1300). Larger input is refused (`E_NOT_OK` on the client, NRC 0x13 from the server). The client exchange log keeps the last `UDS29_LOG_DEPTH` (32) entries.
- One client and one server instance per process (all state is global); a process may host both. One request in flight; the blocking and non-blocking client flows cannot run at the same time. The server does not track separate tester connections: authentication state is per ECU, not per transport channel.
- Server: sub-functions 0x04-0x07 are answered with NRC 0x12; no OCSP, CRLs are read when the identity loads (no reload, no fetching); the auth timeout is measured from the last state change, not from activity. Access control: one rule table per ECU, no per-session-type rules; your dispatcher must call `Uds29Srv_CheckAccess` for every service.
- Client and server share one OS lock: in one process, a blocking client call waits out its transport timeout if the server answers from another thread (use the non-blocking client API, see [docs/transports.md](docs/transports.md)).
- Client non-blocking timeout granularity is the `MainFunction` period; `Uds29_Os_GetTimeMs` wraps after ~49 days (handled by unsigned subtraction). A stray or oversize `RxIndication` is rejected, not treated as a failure. No retry.
- The proof-of-ownership signature covers the raw challenge by default; other compositions (`pown`, presets) are configurable but **not verified against the ISO 14229-1 byte layout** - configure to match your OEM / ISO spec and verify against a reference tester. The ephemeral public key field is sent empty; no session key is derived, so no secured communication follows authentication.
- Ed25519 PKI is OpenSSL-only; the mbedTLS backend returns `E_NOT_OK`.
- Tested on Linux only (GCC, OpenSSL and mbedTLS). The FreeRTOS port and example are compile-checked against the kernel headers (posix port), never run on a target. The QNX and arm-none-eabi toolchain files and the DoIP demo on QNX are untested here. No Windows support.
- The DoIP and CAN demos are demonstration transports. DoIP: TCP only (no UDP discovery), no TLS, one tester at a time, loopback by default; compatibility with other DoIP entities (for example niketdhale/DOIP_ECU_Simulator) is by the standard and was not tested. CAN: a userspace ISO-TP (classic CAN, 4095 bytes); the SocketCAN demos compile but were **not run** (the development machine has no CAN support in its kernel); only the ISO-TP code over an in-process loopback driver is tested.
- Server NRCs: 0x51 (bad certificate signature) is OpenSSL only, mbedTLS answers 0x52. The lockout counter is global, not per tester (a hostile tester can lock out the real one). 0x5A, 0x5B and 0x5D are never sent. The NRC mapping follows py-uds 4.1.0 names, not a reading of the paywalled ISO text.
- The IDSM bridge is fire-and-forget: it ignores `IdsM_ReportEvent` errors; IDSM forwards to DEM asynchronously.

## License

MIT, see [LICENSE](LICENSE).
