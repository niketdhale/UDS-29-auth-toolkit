#pragma once
/* ECU (server) side of SID 0x29: sub-functions 0x00, 0x01, 0x02, 0x03 and 0x08 (others -> NRC 0x12).
   Plain C11, static memory, same crypto and OS ports as the client. One ECU instance per process.
   Built when UDS29_ROLE is SERVER or BOTH. */
#include "Uds29_Types.h"
#include "Uds29_Cfg.h"
#include "Uds29_Authz.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Uds29_PkiConfigType pki;        /* ECU identity + root CA; UDS29_PKI_SAMPLE uses certs/sample/ecu_* */
    uint8_t             challenge_len; /* 1..UDS29_MAX_CHALLENGE_LEN; 0 = 32 */
    uint32_t            auth_timeout_ms; /* 0 = off. Unauthenticated again this long after the last accepted
                                            0x01/0x02 (waiting for 0x03) or after authentication completed */
    const Uds29_CertProfile* profile;    /* NULL = the certificate grants nothing (roles 0, no allow-lists). Else how
                                            to read roles / allow-lists from the client certificate (must outlive the server) */
    uint32_t            required_roles;  /* 0 = off. Else the certificate must carry at least one of these role bits
                                            to authenticate, or NRC 0x56 */
    uint8_t             deny_nrc;        /* NRC for denied access: 0 = 0x34 authenticationRequired, or e.g. 0x33 */
    bool                deny_unlisted_sid; /* false: a SID without any access rule is allowed; true: denied */
    Uds29_CertPolicy    policy;          /* applied to the tester certificate; all-zero = chain + validity only */
    Uds29_PownFormat    pown;            /* signed data of the proofs of ownership; must match the tester's. Default: raw challenge */
} Uds29Srv_ConfigType;

/* Opt-in certificate validation, see docs/certificate-validation.md. NRCs: certificate revoked (CRL or serial
   list) / chain invalid 0x52, validity or no trusted time 0x50, key usage / EKU / algorithm policy 0x56, unparsable 0x54.
   Intermediates and CRLs are part of `pki`. Time source for time_mode HOOK; NULL removes it. */
Std_ReturnType  Uds29Srv_SetTimeSource(Uds29_TimeSourceFn fn, void* ctx);
/* Serial blacklist (not copied, must outlive its use; NULL / 0 removes it). A tester certificate with one of these serials -> NRC 0x52. */
Std_ReturnType  Uds29Srv_SetRevokedSerials(const Uds29_Serial* list, uint16_t count);

/* Loads the identity; E_NOT_OK on bad files, key/cert mismatch, invalid chain or bad challenge_len. */
Std_ReturnType  Uds29Srv_Init(const Uds29Srv_ConfigType* config);
Std_ReturnType  Uds29Srv_DeInit(void);
/* DCM-style: req is a full 0x29 request (SID included). Writes a positive (0x69) or negative (7F 29 nrc)
   response to resp; *resp_len = capacity in, length out. Returns E_OK if a response was written,
   E_MODE_INVALID if not initialised, E_NOT_OK if the response does not fit. */
Std_ReturnType  Uds29Srv_HandleRequest(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len);
/* Call cyclically: enforces auth_timeout_ms (-> unauthenticated). HandleRequest enforces it too. */
void            Uds29Srv_MainFunction(void);
bool            Uds29Srv_IsAuthenticated(void);
/* IDLE, CERT_SENT (client cert accepted, challenge issued, waiting for 0x03), AUTHENTICATED.
   A rejected certificate/proof returns to IDLE. */
Uds29_StateType Uds29Srv_GetState(void);
/* Events: state changes, and a failure event for every NRC sent (nrc != 0) or auth timeout (nrc == 0). */
void            Uds29Srv_SetEventCallback(Uds29_EventCallback cb);

/* ── Access control ──
   A rule grants `roles` (mask; 0 = any authenticated client) the use of a service, optionally for one
   sub-function / DID / RID. Identifier per SID: 0x22 / 0x2E -> DID (bytes 1-2; 0x22 checks every DID in the
   request), 0x31 -> RID (bytes 2-3), 0x10 0x11 0x27 0x28 0x85 -> sub-function (bit 7 ignored), all other SIDs
   (and truncated requests) -> UDS29_ANY. A request is allowed if any rule of its SID matches (same id or
   UDS29_ANY) and the certificate has one of its roles. A SID that has rules but no granting one is DENIED;
   a SID with no rule at all is allowed (or denied with deny_unlisted_sid). SIDs 0x29 and 0x3E are always allowed. */
#define UDS29_ANY 0xFFFFu
typedef struct { uint8_t sid; uint16_t sub_or_id; uint32_t roles; } Uds29Srv_AccessRule;

/* Replaces the certificate parsing of the profile (exotic OEM formats). Called after the chain check with the
   client certificate; E_NOT_OK rejects it with NRC 0x55. NULL removes the hook. */
typedef Std_ReturnType (*Uds29Srv_AuthzParser)(const uint8_t* cert_der, uint16_t len, Uds29_Authz* out, void* ctx);
void           Uds29Srv_SetAuthzParser(Uds29Srv_AuthzParser fn, void* ctx);
/* rules is not copied: it must outlive its use. NULL / 0 removes the policy. */
void           Uds29Srv_SetAccessRules(const Uds29Srv_AccessRule* rules, uint16_t count);
/* Checks a full request (SID included) against the policy and the certificate allow-lists of the authenticated
   client. E_OK = allowed; E_NOT_OK = denied, *nrc = deny_nrc (default 0x34). Call it before dispatching any
   service other than 0x29. Also use the certificate's allow-lists: services[] / dids[] / rids[] when not empty. */
Std_ReturnType Uds29Srv_CheckAccess(const uint8_t* req, uint16_t len, uint8_t* nrc);
/* Copies the authorization of the authenticated client; E_NOT_OK (and *out zeroed) if not authenticated. */
Std_ReturnType Uds29Srv_GetAuthz(Uds29_Authz* out);

#ifdef __cplusplus
}
#endif
