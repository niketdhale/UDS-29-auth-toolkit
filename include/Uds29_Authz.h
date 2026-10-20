#pragma once
/* Certificate-based access control, server side. A client certificate carries a role mask and optional
   allow-lists (services, DIDs, RIDs); the OEM decides where and how they are encoded by filling a
   Uds29_CertProfile (config only), or by registering a parser callback (Uds29Srv_SetAuthzParser).
   The access policy (which role may use which service / DID / RID) lives in the ECU: Uds29Srv_SetAccessRules. */
#include "Uds29_Types.h"
#include "Uds29_Cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What the certificate grants. An empty list means "no restriction from the certificate". */
typedef struct {
    uint32_t roles;                       /* bit mask, meaning defined by the OEM */
    uint8_t  services[UDS29_MAX_ALLOW];   uint8_t n_services;
    uint16_t dids[UDS29_MAX_ALLOW];       uint8_t n_dids;
    uint16_t rids[UDS29_MAX_ALLOW];       uint8_t n_rids;
} Uds29_Authz;

typedef enum { UDS29_AZ_ROLE = 0, UDS29_AZ_SERVICES, UDS29_AZ_DIDS, UDS29_AZ_RIDS } Uds29_AzKind;
typedef enum { UDS29_AZ_EXTENSION_OID = 0, UDS29_AZ_SUBJECT_OU, UDS29_AZ_SUBJECT_CN } Uds29_AzSource;
typedef enum {
    UDS29_AZ_BITSTRING_MASK = 0, /* BIT STRING, ASN.1 named bit i (MSB first) -> role bit i (or id i for lists) */
    UDS29_AZ_INTEGER_MASK,       /* INTEGER (<= 32 bits), bit i set -> role bit i (or id i for lists) */
    UDS29_AZ_OCTETS_ID8,         /* OCTET STRING = concatenated 8-bit ids (big endian) */
    UDS29_AZ_OCTETS_ID16,        /* ... 16-bit ids */
    UDS29_AZ_OCTETS_ID32,        /* ... 32-bit ids (must fit the target: services 8 bit, DIDs/RIDs 16 bit) */
    UDS29_AZ_SEQ_OF_INTEGER,     /* SEQUENCE OF INTEGER; each value is a role bit index (ROLE) or an id */
    UDS29_AZ_STRING_MAP          /* UTF8/Printable/IA5 string looked up in a table (only encoding for OU / CN) */
} Uds29_AzEncoding;

/* STRING_MAP entry: ROLE items OR `value` (a role mask) into roles; list items add `value` as an id. */
typedef struct { const char* str; uint32_t value; } Uds29_AzStringMap;

typedef struct {
    Uds29_AzKind     kind;
    Uds29_AzSource   source;
    Uds29_AzEncoding encoding;
    const char*      oid;           /* EXTENSION_OID: dotted string, e.g. "1.3.6.1.4.1.99999.29.1" ... */
    const uint8_t*   oid_der;       /* ... or the full DER encoding of the OID (06 len ...); used if non-NULL */
    uint8_t          oid_der_len;
    const Uds29_AzStringMap* map;   /* STRING_MAP only */
    uint8_t          map_count;
} Uds29_CertProfileItem;

/* Several items may fill the same kind (their results are merged). Must outlive its use by the server. */
typedef struct { const Uds29_CertProfileItem* items; uint8_t count; } Uds29_CertProfile;

/* Decodes one raw value (the DER inside an extension's OCTET STRING, or the string of an OU / CN) according to
   item->kind / item->encoding and merges it into *out. E_NOT_OK on malformed data, a value that does not fit
   its target or a full list. */
Std_ReturnType Uds29_Authz_Decode(const Uds29_CertProfileItem* item, const uint8_t* value, uint16_t len, Uds29_Authz* out);
/* Applies the whole profile to a DER certificate. *out is cleared first. A missing extension / OU / CN just
   contributes nothing; EXTENSION_OID items need the crypto port's get_extension op (else they contribute nothing).
   E_NOT_OK if a present value is malformed. */
Std_ReturnType Uds29_Authz_FromCert(const Uds29_CertProfile* profile, const uint8_t* cert_der, uint16_t len, Uds29_Authz* out);

#ifdef __cplusplus
}
#endif
