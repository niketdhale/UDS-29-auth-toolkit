# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-10-21

### Added
- Server: `supported_comm_config_mask` (communicationConfiguration values 0..7 accepted by 0x01/0x02, else NRC 0x5C; 0 = any), opt-in lockout `max_failed_attempts` / `lockout_delay_ms` (NRC 0x36 on the failure reaching the limit, 0x37 for 0x01/0x02/0x03 until the delay expires; failure events "attempts exceeded" / "lockout"), `Uds29Srv_GetFailedAttempts`, `Uds29Srv_ResetLockout`, and `nrc_collapse`. All zero/false = off.
- `Uds29_PkiResult`: `UDS29_PKI_SIGNATURE` (OpenSSL `CERT_SIGNATURE_FAILURE`; mbedTLS cannot tell it from an untrusted chain and still returns CHAIN), `UDS29_PKI_POLICY_USAGE`, `UDS29_PKI_POLICY_ALG` (appended; `UDS29_PKI_POLICY` kept). `UDS29_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS` (0x36), `UDS29_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED` (0x37); `Uds29_Codec_NrcToString` names them. IDSM defaults: 0x36 HIGH, 0x37 MEDIUM. Client failure events distinguish "signature invalid" and "algorithm not allowed".

### Changed
- **Behaviour change: server NRCs now follow the ISO 14229-1 meanings** ([docs/certificate-validation.md](docs/certificate-validation.md) has the full table):

  | Failure | 0.5.0 | 0.6.0 |
  | --- | --- | --- |
  | certificate revoked (CRL, serial blacklist) | 0x52 | **0x57** |
  | keyUsage / EKU missing | 0x56 | **0x53** |
  | key type / signature algorithm not allowed | 0x56 | **0x53** |
  | bad certificate signature (OpenSSL) | 0x52 | **0x51** |
  | chain invalid, role mismatch, validity, format, proof | unchanged | unchanged |

  To keep the 0.5.0 responses set `Uds29Srv_ConfigType.nrc_collapse = true` (0x51 / 0x57 -> 0x52, 0x53 -> 0x56). A tester or IDSM mapping that matched 0x52 / 0x56 for these cases must be updated otherwise.
- `Uds29Srv_ConfigType` has four new trailing fields (zero = off).

### Known limitations
- 0x51 is OpenSSL only. The lockout counter is global, not per tester. The mapping follows py-uds 4.1.0, not the ISO text.

## [0.5.0] - 2026-10-21

### Added
- **Certificate validation hardening**, all opt-in with the defaults of 0.4 ([docs/certificate-validation.md](docs/certificate-validation.md)):
  - Intermediate CAs: `Uds29_PkiConfigType.intermediate_paths[]` (`UDS29_MAX_INTERMEDIATES`, default 2); chained through, never trust anchors; a peer presents its leaf only.
  - Revocation: `crl_paths[]` (OpenSSL `CRL_CHECK` / `CRL_CHECK_ALL`, mbedTLS `ca_crl`; stale CRL fails closed) and serial blacklist `Uds29_SetRevokedSerials` / `Uds29Srv_SetRevokedSerials`. New `UDS29_PKI_REVOKED` -> server NRC 0x52.
  - `Uds29_CertPolicy` (`policy` in `Uds29_ConfigType` and `Uds29Srv_ConfigType`): keyUsage digitalSignature, required EKU OID, allowed key types (P-256, P-384, Ed25519) and certificate signature algorithms; checked in the core by a DER walk, backend independent. New `UDS29_PKI_POLICY` -> server NRC 0x56.
  - Trusted time: `Uds29_SetTimeSource` / `Uds29Srv_SetTimeSource`, `time_mode` SYSTEM / HOOK / SKIP_WITH_EVENT, optional monotonic guard. New `UDS29_PKI_TIME_UNTRUSTED` -> NRC 0x50; new event kind `UDS29_EVT_WARNING` ("validity not checked").
  - Proof-of-ownership data composition `Uds29_PownFormat` (`pown` in both configs): server / client challenge, additional parameter, SHA-256 of own / peer certificate; presets `UDS29_POWN_PRESET_RAW_CHALLENGE` (default) and `UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE` (not claimed to be the ISO 14229-1 layout).
  - Crypto port: optional `sha256` op, `UDS29_AT_SKIP_VALIDITY` for `verify_peer_cert`, `UDS29_PKI_*` results; intermediate / CRL paths in `load_identity`.
- Sample PKI: sub-CA (`sub_ca.pem`), `tester_subca`, `tester_revoked` with `root_crl.pem`, `sub_ca_crl.pem`, `root_crl_stale.pem`, `tester_p384`, `tester_sha384`, `tester_future`; keyUsage + example EKUs (`.100` tester, `.101` ECU) on all end-entity certificates. **The sample root and all sample certificates were regenerated.**
- CLI: `pki load ... [--inter f]... [--crl f]...`; `cert inspect` prints serial, key type, signature algorithm, keyUsage, EKU and the chain result against the loaded PKI.
- `tests/test_validation.cpp`.

### Changed
- `Uds29_PkiConfigType`, `Uds29_ConfigType` and `Uds29Srv_ConfigType` have new trailing fields (zero = off). Source compatible; positional partial initialisers warn with `-Wmissing-field-initializers` (the in-tree tests and examples build with `-Wno-missing-field-initializers`). `Uds29_CryptoOpsType` has a new trailing `sha256` member (NULL allowed).
- In HOOK and SKIP time mode the own certificate is not date-checked when the identity loads.

### Known limitations
- No OCSP; CRLs are read when the identity loads. mbedTLS does not flag an issuer that has no CRL in the list (OpenSSL does when intermediates are used). The proof-of-ownership presets are unverified against the ISO text.

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
