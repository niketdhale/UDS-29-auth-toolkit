# Access control from certificates

SID 0x29 proves *who* the tester is. This part of the server decides *what that tester may do*, using information the
OEM put into the tester's certificate. Server side only (`UDS29_ROLE=SERVER` or `BOTH`).

```text
 Tester certificate                  Profile or parser hook
 roles + allow-lists ──0x29 01/02──▶ (OEM format)
                                            │
                                            ▼
                                     Uds29_Authz
                                     roles, services[], dids[], rids[]
                                            │
 Access rules (ECU policy)                  ▼
 SID / sub / DID / RID → roles ─────▶ Uds29Srv_CheckAccess
                                            │
                          ┌─────────────────┴─────────────────┐
                          ▼ E_OK                              ▼ E_NOT_OK
                  your service handler              7F <sid> 34 (NRC 0x34)
```

- The **certificate** says: this holder has roles `R` (a bit mask) and, optionally, may only use these services, DIDs
  and routines (allow-lists). It is signed by the OEM's CA, so it cannot be edited.
- The **ECU** says: service X (optionally for sub-function / DID / RID Y) needs one of these roles. This is the access
  rule table, compiled into the ECU.
- The two combine in `Uds29Srv_CheckAccess()`. The roles in the certificate are only labels; the ECU's table gives them
  meaning, so one certificate profile can serve ECUs with different policies.

This is the same split as in an AUTOSAR stack: KeyM manages certificates, Csm does the crypto, and Dcm keeps an
authentication state with roles and checks it per service, DID and routine, answering NRC 0x34
(authenticationRequired) when it fails. libuds29 does not implement those modules; `Uds29_CertProfile` plays the part of the
certificate-to-role mapping and the rule table plays the part of the Dcm configuration.

## What the certificate carries: `Uds29_Authz`

```c
typedef struct {
    uint32_t roles;                                    /* bit mask, meaning defined by the OEM */
    uint8_t  services[UDS29_MAX_ALLOW];  uint8_t n_services;   /* SIDs */
    uint16_t dids[UDS29_MAX_ALLOW];      uint8_t n_dids;
    uint16_t rids[UDS29_MAX_ALLOW];      uint8_t n_rids;
} Uds29_Authz;
```

An **empty list means no restriction from the certificate**; a non-empty one narrows what the access rules would
otherwise grant. `UDS29_MAX_ALLOW` (`Uds29_Cfg.h`, default 32) bounds each list; a certificate with more entries is
rejected at authentication, never silently truncated (a truncated allow-list would be too narrow, or empty = open).
`Uds29Srv_GetAuthz(&a)` returns the authorization of the currently authenticated client.

## How an OEM defines its certificate format

The format is configuration, not code. Four steps.

**1. Choose OIDs under your own Private Enterprise Number.** Register a PEN with IANA (free) and reserve an arc, for
example `1.3.6.1.4.1.<PEN>.7`: `.7.1` roles, `.7.2` allowed services, `.7.3` allowed DIDs, `.7.4` allowed routines.
The sample PKI of this repository uses `1.3.6.1.4.1.99999.29.x`: **99999 is an example, not a registered number.**
Make the extensions non-critical, so that tools which do not know them still accept the certificate.

**2. Choose an encoding per item.**

| Encoding | ASN.1 value | Meaning |
| --- | --- | --- |
| `BITSTRING_MASK` | `BIT STRING` | named bit *i* (MSB first) set: role bit *i* (for a list kind: id *i*) |
| `INTEGER_MASK` | `INTEGER`, up to 32 bits, not negative | bit *i* set: role bit *i* (list kind: id *i*) |
| `OCTETS_ID8` / `_ID16` / `_ID32` | `OCTET STRING` | concatenated big-endian ids of 1 / 2 / 4 bytes |
| `SEQ_OF_INTEGER` | `SEQUENCE OF INTEGER` | each value is a role bit index (ROLE) or an id (lists) |
| `STRING_MAP` | `UTF8String` / `PrintableString` / `IA5String`; for OU and CN the plain string | looked up in a table: ROLE ORs the entry's role mask, a list kind adds the entry's value as id |

Ids must fit the target (services 8 bit, DIDs and RIDs 16 bit, role bit index below 32), or the certificate is rejected.
Sources: `EXTENSION_OID` (any encoding), `SUBJECT_OU` and `SUBJECT_CN` (only `STRING_MAP`, every matching attribute is looked up).
Several items may fill the same kind; their results merge (roles are ORed, lists appended).

**3. Fill a `Uds29_CertProfile`.** Complete example of a made-up OEM "ACME" (PEN 12345): roles as an `INTEGER` mask
(bit 0 workshop, bit 1 engineering, bit 2 oem), allowed services as a `SEQUENCE OF INTEGER`, allowed DIDs as an `OCTET STRING`
of 16-bit ids, and as a fallback roles from the subject OU of older certificates:

```c
#include "Uds29_Server.h"

enum { ROLE_WORKSHOP = 1, ROLE_ENGINEERING = 2, ROLE_OEM = 4 };

static const Uds29_AzStringMap kOuRoles[] = {{"workshop", ROLE_WORKSHOP}, {"engineering", ROLE_ENGINEERING}, {"oem", ROLE_OEM}};

static const Uds29_CertProfileItem kItems[] = {
    /* kind               source                  encoding                oid                       oid_der n  map        n */
    {UDS29_AZ_ROLE,     UDS29_AZ_EXTENSION_OID, UDS29_AZ_INTEGER_MASK,  "1.3.6.1.4.1.12345.7.1",   0, 0, 0,        0},
    {UDS29_AZ_SERVICES, UDS29_AZ_EXTENSION_OID, UDS29_AZ_SEQ_OF_INTEGER,"1.3.6.1.4.1.12345.7.2",   0, 0, 0,        0},
    {UDS29_AZ_DIDS,     UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID16,   "1.3.6.1.4.1.12345.7.3",   0, 0, 0,        0},
    {UDS29_AZ_ROLE,     UDS29_AZ_SUBJECT_OU,    UDS29_AZ_STRING_MAP,    0,                        0, 0, kOuRoles, 3},
};
static const Uds29_CertProfile kProfile = {kItems, 4};

Uds29Srv_ConfigType cfg = {0};
cfg.pki = (Uds29_PkiConfigType){UDS29_PKI_USER, "ca.pem", "ecu.pem", "ecu.key", UDS29_PKI_FORMAT_PEM};
cfg.profile = &kProfile;                       /* must stay valid while the server runs */
cfg.required_roles = ROLE_WORKSHOP | ROLE_ENGINEERING | ROLE_OEM;  /* optional: no role at all = NRC 0x56 */
cfg.deny_nrc = 0;                              /* 0 = 0x34 authenticationRequired; 0x33 securityAccessDenied also common */
Uds29Srv_Init(&cfg);
```

The OID can instead be given as DER (`oid_der` = `06 len ...`, `oid_der_len`) when you do not want the dotted string in flash.

**4. Issue certificates with those extensions.** With `openssl`, `ASN1:` and `FORMAT:` build the values (config `acme.cnf`):

```ini
[acme_engineer]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
1.3.6.1.4.1.12345.7.1 = ASN1:INTEGER:2                  # role mask: engineering
1.3.6.1.4.1.12345.7.2 = ASN1:SEQUENCE:services          # only SIDs 22 and 19
1.3.6.1.4.1.12345.7.3 = ASN1:FORMAT:HEX,OCTETSTRING:F190F18C

[services]
s1 = INTEGER:0x22
s2 = INTEGER:0x19
```

```sh
openssl req -new -key tester.key -subj "/CN=Tester 17/OU=engineering" -out tester.csr
openssl x509 -req -in tester.csr -CA oem_ca.pem -CAkey oem_ca.key -CAcreateserial -sha256 -days 365 \
    -extfile acme.cnf -extensions acme_engineer -out tester.pem
```

The repository's own sample certificates are made this way: `certs/sample/oem_profile.cnf` and
`certs/sample/gen_sample_certs.sh` (BIT STRING roles, `OCTET STRING` services and DIDs). The matching profile is
`examples/access_example.h`.

Extension values are read through the crypto port: OpenSSL (`X509_get_ext_by_OBJ`) and mbedTLS (walk of the v3
extensions) are built in; a custom backend (`UDS29_CRYPTO=CUSTOM` / HSM) may provide the optional `get_extension` op of
`Uds29_CryptoOpsType` (NULL = extension items contribute nothing). OU and CN do not need the op, they are read by the
library's own bounded DER parser.

### A format the profile cannot express: the parser hook

For anything else (roles in an X.509 attribute certificate, a private ASN.1 structure, a lookup in your own database
by serial number), replace the profile:

```c
static Std_ReturnType MyParser(const uint8_t* cert_der, uint16_t len, Uds29_Authz* out, void* ctx) {
    /* *out is zeroed. Fill roles / lists from cert_der (DER of the client certificate, chain already verified).
       Return E_NOT_OK to reject the certificate: the client gets NRC 0x55. */
    uint32_t serial_role = LookupRole(cert_der, len, ctx);
    if (!serial_role) return E_NOT_OK;
    out->roles = serial_role;
    out->services[out->n_services++] = 0x22;
    return E_OK;
}
Uds29Srv_SetAuthzParser(MyParser, &my_db);     /* overrides cfg.profile; NULL removes it */
```

A parser that reports counts above `UDS29_MAX_ALLOW` is rejected too.

## The ECU policy: access rules

```c
typedef struct { uint8_t sid; uint16_t sub_or_id; uint32_t roles; } Uds29Srv_AccessRule;   /* UDS29_ANY = 0xFFFF */

static const Uds29Srv_AccessRule kRules[] = {
    {0x22, UDS29_ANY, ROLE_WORKSHOP | ROLE_ENGINEERING | ROLE_OEM},  /* read any DID */
    {0x2E, 0xF190,    ROLE_ENGINEERING | ROLE_OEM},                  /* write the VIN */
    {0x2E, UDS29_ANY, ROLE_OEM},                                     /* write any other DID */
    {0x31, UDS29_ANY, ROLE_ENGINEERING | ROLE_OEM},                  /* routines */
    {0x34, UDS29_ANY, ROLE_OEM}, {0x36, UDS29_ANY, ROLE_OEM}, {0x37, UDS29_ANY, ROLE_OEM},   /* flashing */
};
Uds29Srv_SetAccessRules(kRules, sizeof kRules / sizeof *kRules);       /* not copied: keep it valid */
```

In your service dispatcher, before executing any SID except 0x29:

```c
uint8_t nrc;
if (Uds29Srv_CheckAccess(req, len, &nrc) != E_OK) { /* send 7F req[0] nrc */ }
```

Rules of the check:

| What | Behaviour |
| --- | --- |
| Identifier | `0x22`, `0x2E`: DID in bytes 1-2 (for `0x22` **every** DID in the request must be granted); `0x31`: RID in bytes 2-3; `0x10 0x11 0x27 0x28 0x85`: the sub-function (bit 7 ignored); every other SID, and a truncated request: `UDS29_ANY` |
| Match | a rule matches when `sid` is equal and `sub_or_id` is `UDS29_ANY` or equals the identifier; it grants when `roles` is 0 (any authenticated client) or shares a bit with the certificate's roles. One granting rule is enough |
| SID with rules | not authenticated, or no granting rule: **denied**. A rule for `0x2E F190` does not open `0x2E F187` |
| SID without any rule | **allowed** (also when unauthenticated) unless `deny_unlisted_sid` is set, which denies it. Decide this deliberately: list every service you want protected |
| `0x29`, `0x3E` | always allowed |
| Certificate allow-lists | after the rules, for an authenticated client: if `services[]` is not empty the SID must be in it (this also narrows SIDs without a rule); for `0x22`/`0x2E` every DID must be in a non-empty `dids[]`; for `0x31` the RID in a non-empty `rids[]` |
| NRC | `deny_nrc`, default `0x34` authenticationRequired (use `0x33` securityAccessDenied if your OEM prefers) |

A denial also raises a server event (`kind == FAILURE`, `description` "access denied", `nrc`), so the IDSM bridge reports it.
Authentication state and authorization are dropped together (de-authentication, timeout, rejected certificate).

## CLI

`uds29_cli` (client mode) prints what a certificate carries, decoded with the example profile of
`examples/access_example.h`:

```
$ ./build/uds29_cli
> cert inspect certs/sample/tester_allowlist_cert.pem
subject: CN=UDS29 Sample Allowlist Tester, OU=oem
issuer:  CN=UDS29 Sample Root CA
valid:   2026-10-20 15:25:18 .. 2036-10-17 15:25:18 UTC
authz (example profile 1.3.6.1.4.1.99999.29.x): roles=0x00000004 oem
  services: 22 3E
  dids:     F190 F18C
  rids:     (any)
```

(`cert inspect <file> [der]`; PEM by default.) In server mode the example rules are active and the policy can be
queried; `login` authenticates a sample tester inside the same process so there is someone to check:

```
$ printf 'access 22 F1 90\nlogin certs/sample/tester_workshop_cert.pem certs/sample/tester_workshop_key.pem\naccess 22 F1 90\naccess 2E F1 90 41\n' | ./build/uds29_cli --role server
DENIED 7F 22 34
LOGIN OK
ALLOWED
DENIED 7F 2E 34
```

Also available: `logout` and `authz`.

## Demo

`examples/access_control_demo.c` (ctest `example_access_control`) runs tester and ECU in one process with the four sample
certificates and the example rules, and exits non-zero if any outcome differs from the expectation:

```
== not authenticated
  read VIN                  22 F1 90
                            -> 7F 22 34   denied
== tester_workshop
  authenticated: roles=0x01 services=0 dids=0 rids=0 allow-list entries
  read VIN                  22 F1 90
                            -> 62 F1 90   allowed
  write VIN                 2E F1 90 41
                            -> 7F 2E 34   denied
  request download (flash)  34 00 44 00 00 00 00 00 00 10 00
                            -> 7F 34 34   denied
== tester_oem
  write F187                2E F1 87 01
                            -> 6E F1 87   allowed
  request download (flash)  34 00 44 00 00 00 00 00 00 10 00
                            -> 74 00 44   allowed
== tester_allowlist
  authenticated: roles=0x04 services=2 dids=2 rids=0 allow-list entries
  read F187                 22 F1 87
                            -> 7F 22 34   denied
PASS
```
(excerpt; the positive responses are stubs of the demo's fake DCM.)

## Limits

- Authorization is as trustworthy as the CA that issues the certificates and the ECU's rule table. There is no revocation.
- The access check is advisory plumbing: your dispatcher must call `Uds29Srv_CheckAccess` for every service. The library
  cannot see requests you do not pass to it.
- One authenticated client per ECU (the server has no per-connection state), and roles are not re-read while the session lasts.
- Roles, allow-list sizes and the encodings above are what is implemented; no per-session-type rules (default vs extended
  session), no time-limited roles.
