# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-10-20

### Added
- **ECU server** (`Uds29_Server.h`, plain C11, static memory): `Uds29Srv_HandleRequest` for sub-functions 0x00-0x03 and 0x08, NRCs 0x12/0x13/0x24/0x50-0x58, auth timeout via `Uds29Srv_MainFunction`, event callback.
- `UDS29_ROLE=CLIENT|SERVER|BOTH` build option; `uds29_cli --role server`.
- **Certificate-based access control** (`Uds29_Authz.h`):
  - OEM-defined certificate profile (config only): role / services / DIDs / RIDs read from an X.509 extension OID, subject OU or CN, with BIT STRING, INTEGER, OCTET STRING (8/16/32-bit IDs), SEQUENCE OF INTEGER or string-map encodings.
  - Custom parser hook `Uds29Srv_SetAuthzParser` for other formats.
  - Access rule table `Uds29Srv_SetAccessRules` and `Uds29Srv_CheckAccess` (NRC 0x34 by default, configurable).
  - Crypto-port op `get_extension` for OpenSSL and mbedTLS.
  - Sample workshop, engineering, OEM and allow-list tester certificates (`certs/sample/oem_profile.cnf`, example OID arc `1.3.6.1.4.1.99999.29.x`).
  - CLI `cert inspect`; server-mode `access`, `login`, `logout`, `authz`; `examples/access_control_demo.c`.
- **Transports** (`examples/transports/`): DoIP (ISO 13400-2) client/server demos; userspace CAN ISO-TP (ISO 15765-2) over SocketCAN or an in-memory loopback, with client/server demos.
- IDSM bridge can attach to the server (`Uds29_IdsM_InitServer`).
- Docs: `docs/linux.md`, `qnx.md`, `freertos.md`, `client-server.md`, `transports.md`, `access-control.md`; README rewritten with badges and diagrams.
- CI: role matrix, DoIP two-process test, ISO-TP/authz tests, SocketCAN job (continue-on-error).

### Changed
- `Uds29SimEcu` is now a thin wrapper over the server.

### Known limitations
- SocketCAN demos, QNX and FreeRTOS runtime not tested; client and server share one OS lock (use the non-blocking client API when both run in one process).

## [0.3.0] - 2026-10-20

### Added
- Non-blocking AUTOSAR-style client API: `Uds29_StartAuthentication`, `Uds29_StartDeAuthentication`, `Uds29_MainFunction`, `Uds29_RxIndication`, `Uds29_SetTxCallback`, per-step timeout `UDS29_P2_TIMEOUT_MS`.
- Crypto port (`Uds29_Crypto.h`): OpenSSL, mbedTLS 3.x or custom ops (`Uds29_SetCryptoOps`) for HSM/PKCS#11.
- OS port (`Uds29_Os.h`): POSIX (Linux, QNX) and FreeRTOS.
- Static or shared library, `cmake --install`, `find_package(uds29)`, `uds29.pc`; toolchain files for QNX aarch64le and arm-none-eabi.
- Examples: `linux_app.c`, `freertos_task.c`, `consumer/`.
- `.gitattributes` forcing LF line endings; GitHub Actions CI.

### Changed
- Core rewritten in plain C11 with static buffers sized in `Uds29_Cfg.h`; no heap or exceptions in the core.
- Exchange log is a ring of `UDS29_LOG_DEPTH` entries (was unbounded).
- `Uds29_Init` rejects `challenge_len > UDS29_MAX_CHALLENGE_LEN`; `Uds29_SendRaw` rejects requests over `UDS29_MAX_MSG_LEN`.

### Removed
- Internal C++ classes `Uds29Pki`, `Uds29Codec`, `Uds29_Bytes` (replaced by `Uds29_Codec_*` and the crypto port).

### Fixed
- Leftover merge conflict markers in `CMakeLists.txt` and `.gitignore`; executable bit on `gen_sample_certs.sh`.

## [0.2.0] - 2026-10-20

### Added
- Interactive CLI `uds29_cli` (works from piped stdin).
- Optional IDSM bridge (`-DUDS29_ENABLE_IDSM=ON`) reporting authentication events to `IdsM_ReportEvent`, with configurable monitor ID and per-NRC event ID / severity / enable.
- README.

## [0.1.0] - 2026-10-20

### Added
- Codec for all 0x29 sub-functions 0x00-0x08 and negative responses.
- PKI with sample certificates or user PEM/DER files; chain, validity and key-match checks; ECDSA P-256 and Ed25519.
- Session manager for unidirectional and bidirectional authentication, deAuthenticate, exchange log, event callback.
- Protocol-independent transport callback.
- Simulated ECU with fault injection.
- Google Test suites.

[0.4.0]: https://github.com/niketdhale/UDS-29-auth-toolkit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/niketdhale/UDS-29-auth-toolkit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/niketdhale/UDS-29-auth-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/niketdhale/UDS-29-auth-toolkit/releases/tag/v0.1.0
