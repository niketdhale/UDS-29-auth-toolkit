# Certificate validation

Everything the library checks on the **peer** certificate: the tester's on the server (`Uds29Srv_*`), the ECU's on the
client (`Uds29_*`, bidirectional only). Both sides run the same pipeline, so one configuration vocabulary serves both.
Every option below is opt-in; a zero-initialised config is the behaviour of 0.4: chain to the root CA and validity
period against the system clock, nothing else.

```text
 peer cert ─▶ trusted time ─▶ backend: signature chain (+ intermediates), CA constraints, dates, CRL
                                │ failure ─▶ PARSE / EXPIRED / CHAIN / REVOKED
                                ▼
                 serial blacklist ─▶ keyUsage ─▶ EKU ─▶ key type ─▶ signature algorithm   (core, DER walk)
                                │ failure ─▶ REVOKED / POLICY
                                ▼
                 server only: authz profile / required_roles ─▶ challenge ─▶ proof of ownership
```

The core checks (blacklist, key usage, EKU, algorithms) read the certificate with a small bounded DER walk
(`src/Uds29_Der.h`), so they behave the same with OpenSSL, mbedTLS and a custom HSM backend.

## Every check

| # | Check | Configured with | Default | Server NRC | Client (ECU certificate) |
| --- | --- | --- | --- | --- | --- |
| 1 | Certificate parses | - | on | 0x54 invalidFormat | fails, "unparsable" |
| 2 | Signature chain to the root CA, `basicConstraints` / `pathLen` (done by the library) | `root_ca_path` | on | 0x52 invalidChainOfTrust | fails, "chain invalid" |
| 3 | Chain through intermediate CAs | `Uds29_PkiConfigType.intermediate_paths[]` (max `UDS29_MAX_INTERMEDIATES`, 2) | none | 0x52 if the chain cannot be built | same |
| 4 | Validity period (`notBefore` / `notAfter`) | `policy.time_mode` | on, system clock | 0x50 invalidTimePeriod | fails, "expired" |
| 5 | Trusted time available / not going back | `policy.time_mode`, `time_monotonic_guard`, `Uds29(Srv)_SetTimeSource` | system clock, no guard | 0x50 | fails, "no trusted time" |
| 6 | CRL (signature, `nextUpdate`, revoked serials) | `Uds29_PkiConfigType.crl_paths[]` (max `UDS29_MAX_CRLS`, 3) | none (not checked) | 0x52 | fails, "revoked" / "chain invalid" |
| 7 | Serial blacklist | `Uds29(Srv)_SetRevokedSerials` | none | 0x52 | fails, "revoked" |
| 8 | `keyUsage` present with digitalSignature | `policy.require_key_usage_digital_signature` | off | 0x56 invalidScope | fails, "violates the certificate policy" |
| 9 | `extKeyUsage` lists a given OID | `policy.required_eku_oid` (DER) | off | 0x56 | same |
| 10 | Key type (P-256, P-384, Ed25519) | `policy.allowed_key_types` | 0 = any | 0x56 | same |
| 11 | Certificate signature algorithm (ecdsa-with-SHA256 / SHA384, Ed25519) | `policy.allowed_sig_algs` | 0 = any | 0x56 | same |
| 12 | Access rights from the certificate | `profile`, `required_roles` | off | 0x55 / 0x56 | - |
| 13 | Proof of ownership signature, over the configured data | `pown` | raw challenge | 0x58 ownershipVerificationFailed | fails, "proof of ownership invalid" |

A failed check on the server answers the NRC, returns the server to IDLE and emits a failure event. On the client it moves
the session to FAILED and emits a failure event (`nrc` 0: the failure is local, the description says which check).

### NRC mapping (the choices made)

| Result | NRC | Why |
| --- | --- | --- |
| unparsable | 0x54 | as before |
| expired / not yet valid, **no trusted time** | 0x50 | the time period cannot be established |
| chain invalid, **revoked** (CRL or blacklist) | 0x52 | a revoked certificate no longer chains to a trusted anchor; there is no dedicated NRC |
| **policy** (key usage, EKU, key type, signature algorithm) | 0x56 invalidScope | "this certificate is not allowed for this purpose". 0x53 (type) and 0x57 (certificate) are also defensible; ISO 14229-1 is paywalled and this was not verified against it. Change the mapping in `VerifyCert()` (`src/Uds29_Server.c`) if your OEM spec says otherwise |

## Intermediate CAs

```c
Uds29_PkiConfigType pki = { .mode = UDS29_PKI_USER, .root_ca_path = "root.pem", .cert_path = "ecu.pem", .key_path = "ecu.key" };
pki.intermediate_paths[0] = "sub_ca.pem";      /* chained through, never a trust anchor */
```

- The **root** stays the only trust anchor. Intermediates are given to the library as untrusted helper certificates
  (OpenSSL: the untrusted stack of `X509_STORE_CTX_init`; mbedTLS: appended after the leaf in the chain), so `basicConstraints`
  CA:TRUE, `keyCertSign` and `pathLen` of each CA are enforced by the library. A leaf cannot act as a CA.
- The **protocol sends one certificate** (the certificate field of 0x01/0x02), so a peer presents its leaf only and the
  verifier must hold the intermediates. Your own identity is verified through the same intermediates when it is loaded,
  so a leaf issued by a sub-CA only loads if the sub-CA certificate is configured.
- Sample: `certs/sample/sub_ca.pem` (pathLen 0) and `tester_subca_*`.

## Revocation

**CRL.** `crl_paths[]` lists CRL files (PEM or DER as `format`), at most one per CA of the chain (root and intermediates).
They are read when the identity is loaded; to refresh them, call `Uds29_SetPki` / `Uds29Srv_Init` again.

- OpenSSL: `X509_V_FLAG_CRL_CHECK`, plus `CRL_CHECK_ALL` when intermediates are configured. With CRLs configured, a CRL
  that is **missing** for the issuer (for example the root CRL when a sub-CA chain is used) fails the chain.
- mbedTLS: the CRLs are passed as `ca_crl`. An issuer **without** a CRL in the list is *not* flagged (mbedTLS only checks the
  CRLs it has). Configure one CRL per CA on both backends and the behaviour is identical. A CRL file larger than 4 KiB
  is refused by the mbedTLS backend.
- **Freshness.** A CRL past its `nextUpdate` (or before its `thisUpdate`) fails closed as "chain invalid" (0x52), judged at
  the trusted time of check 5. With `SKIP_WITH_EVENT` freshness is not checked either. Plan the CRL distribution
  to the ECU (a diagnostic job, an OTA package) so it never goes stale, or accept that a stale CRL locks authentication out.
- No OCSP and no CRL download: the library never touches the network.

**Serial blacklist.** `Uds29Srv_SetRevokedSerials(list, count)` / `Uds29_SetRevokedSerials(...)` takes
`Uds29_Serial { data, len }` entries (the INTEGER content of the serial; leading zeros are ignored). The list is not copied. It
is a CRL substitute for ECUs that cannot store a CRL, and is checked by the core after the chain verified.
`openssl x509 -serial` prints it in hex.

Revoked: server NRC 0x52; client failure "ECU certificate revoked".

## Key usage, EKU, algorithms

```c
static const uint8_t kEkuTester[] = {0x06,0x0A,0x2B,0x06,0x01,0x04,0x01,0x86,0x8D,0x1F,0x1D,0x64};  /* 1.3.6.1.4.1.99999.29.100 */
cfg.policy.require_key_usage_digital_signature = true;
cfg.policy.required_eku_oid = kEkuTester; cfg.policy.required_eku_oid_len = sizeof kEkuTester;     /* must outlive the server */
cfg.policy.allowed_key_types = UDS29_KEY_EC_P256;
cfg.policy.allowed_sig_algs  = UDS29_SIG_ECDSA_SHA256;
```

- A required extension that is **absent** fails. EKU is matched on the exact OID; `anyExtendedKeyUsage` does not match.
- Key type and signature algorithm are read from the **leaf** only (`SubjectPublicKeyInfo` algorithm and named curve; the
  certificate's `signatureAlgorithm`). Intermediates and the root are not policed; the library's own algorithm support
  limits them. A key type outside the list of three (for example RSA) fails when `allowed_key_types` is set.
- Sample PKI: every tester certificate carries `keyUsage = digitalSignature` and EKU `1.3.6.1.4.1.99999.29.100`, the ECU
  certificate `.101` (both **EXAMPLE** OIDs: replace 99999 with your own Private Enterprise Number). A server requiring
  `.100` therefore rejects the ECU certificate used as a tester certificate (NRC 0x56), and a client requiring `.101` rejects a tester
  certificate presented as an ECU. This is independent of the role OIDs of the access-control profile ([access-control.md](access-control.md)):
  the EKU says *what kind of certificate* it is, the roles say *what its holder may do*.
- Fixtures: `tester_p384` (P-384 key), `tester_sha384` (signed with ecdsa-with-SHA384).

## Trusted time

`policy.time_mode`:

| Mode | Dates are judged against | If no time is available |
| --- | --- | --- |
| `UDS29_TIME_SYSTEM` (default) | `time()` | `time()` <= 0: fails (0x50) |
| `UDS29_TIME_HOOK` | `Uds29_SetTimeSource` / `Uds29Srv_SetTimeSource`: `Std_ReturnType fn(int64_t* unix_s, void* ctx)` | no hook, hook error or time <= 0: **fails closed** (0x50) |
| `UDS29_TIME_SKIP_WITH_EVENT` | nothing: validity of certificates and CRLs is not checked | - |

- `SKIP_WITH_EVENT` emits a `UDS29_EVT_WARNING` event ("validity not checked", `nrc` 0) on every verification and
  continues. It is for ECUs with no trustworthy clock that rely on a blacklist and on rolling their trust anchor; an expired or
  revoked-by-date certificate is then accepted. Use the hook if the ECU can get trusted time (secure time, a signed
  timestamp from a gateway), and use SKIP only knowingly.
- Your **own** certificate is checked when the identity loads. In HOOK and SKIP mode that check ignores dates too (the clock
  at boot is the thing that cannot be trusted).
- **Monotonic guard** (`time_monotonic_guard`, `time_backstep_tolerance_s`): the verifier remembers the latest trusted time
  it used. A source that later reports less than that minus the tolerance fails closed (0x50): an attacker who winds the clock back cannot
  resurrect an expired certificate. The memory lives in RAM and starts at 0 after a reset; it is per side
  (client and server each have their own). Not applied in SKIP mode.
- A test fault (`UDS29SRV_FAULT_EXPIRED_CERT`) still overrides the time and bypasses all of the above; the simulated ECU keeps using it.

## Proof-of-ownership data

Today (default) the signature covers the raw challenge issued by the verifier. `pown` composes other data; **tester and ECU must
use the same format**, on the client in `Uds29_ConfigType.pown`, on the server in `Uds29Srv_ConfigType.pown`.

| Element | Content |
| --- | --- |
| `UDS29_POWN_SERVER_CHALLENGE` | the challenge issued by the ECU |
| `UDS29_POWN_CLIENT_CHALLENGE` | the challenge sent by the tester; **empty in unidirectional** authentication |
| `UDS29_POWN_ADDITIONAL_PARAM` | the `communicationConfiguration` byte of the request (one byte) |
| `UDS29_POWN_PEER_CERT_HASH_SHA256` | SHA-256 of the certificate of the party that verifies the signature |
| `UDS29_POWN_OWN_CERT_HASH_SHA256` | SHA-256 of the signer's certificate |

The elements are concatenated in the order given (`count` 0 = raw challenge = `UDS29_POWN_PRESET_RAW_CHALLENGE`). PEER / OWN are from the
**signer's** point of view (the tester signs in 0x03, the ECU in the 0x02 response). The preset
`UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE` is server challenge || client challenge for bidirectional and the server challenge alone for
unidirectional. **It is not claimed to be the exact ISO 14229-1 byte layout (the specification is not freely
available): configure it to match your OEM / ISO specification and verify against a reference tester.**

Limits: in unidirectional authentication the tester never receives the ECU certificate, so `PEER_CERT_HASH` fails on the
client ("signing failed"); the hash needs `Uds29_CryptoOpsType.sha256` (built in for OpenSSL and mbedTLS, optional for a custom
backend). A mismatch between the two sides appears as NRC 0x58 on the server in unidirectional mode; in bidirectional mode the
client already rejects the ECU's proof ("ECU proof of ownership invalid") before it signs.

## Recommended production profile

```c
/* ECU */
Uds29Srv_ConfigType c = {0};
c.pki = (Uds29_PkiConfigType){ .mode = UDS29_PKI_USER, .root_ca_path = ..., .cert_path = ..., .key_path = ...,
                               .intermediate_paths = {"issuing_ca.pem"}, .crl_paths = {"root.crl", "issuing_ca.crl"} };
c.policy.require_key_usage_digital_signature = true;
c.policy.required_eku_oid = kEkuTester;  c.policy.required_eku_oid_len = sizeof kEkuTester;
c.policy.allowed_key_types = UDS29_KEY_EC_P256;           c.policy.allowed_sig_algs = UDS29_SIG_ECDSA_SHA256;
c.policy.time_mode = UDS29_TIME_HOOK;                     c.policy.time_monotonic_guard = true;
c.policy.time_backstep_tolerance_s = 5;
c.pown = (Uds29_PownFormat)UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE;   /* or what your OEM spec prescribes */
Uds29Srv_Init(&c);
Uds29Srv_SetTimeSource(SecureTime, NULL);
Uds29Srv_SetRevokedSerials(kRevoked, n);                  /* between CRL updates */
```

Mirror it on the tester with the ECU EKU. Use a trusted time source, ship fresh CRLs, keep the blacklist for emergencies.

## Custom crypto backends

`verify_peer_cert` gets `at` = 0 (now), a unix time, or `UDS29_AT_SKIP_VALIDITY` (no date checks, CRL dates included), and
returns `UDS29_PKI_REVOKED` for a CRL hit; `load_identity` receives the intermediate and CRL paths in the config. `sha256` is
optional. A backend that ignores the new config fields keeps the old behaviour. The core never returns `UDS29_PKI_TIME_UNTRUSTED` from a backend.

## Limitations

- No OCSP, no CRL fetching or reloading, no delta CRLs, no CRL distribution point processing; CRLs are read at identity load.
- Revocation of the ECU's own certificate is not checked beyond load time.
- Algorithm policy: leaf only; no RSA support in the policy bitmasks (set a mask and RSA fails); Ed25519 only with OpenSSL.
- A stale CRL or an untrusted time locks authentication out by design (fail closed).
- Time trust is only as good as the hook you provide. In SKIP mode nothing about dates is verified.
- Policy failures all answer NRC 0x56; which check failed is not distinguishable on the wire.
- Tested on Linux with OpenSSL 3 and mbedTLS 3.6; the sample CRLs are valid for ten years and the sample certificates for ten years from generation.
