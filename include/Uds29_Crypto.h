#pragma once
/* Crypto port. Built-in backends: OpenSSL (Ed25519 and ECDSA P-256) and mbedTLS 3.x (ECDSA P-256/SHA-256 only;
   Ed25519 certificates/keys are not supported there and fail with E_NOT_OK / NULL). Register an HSM or PKCS#11
   backend with Uds29_SetCryptoOps (required when built with UDS29_CRYPTO=CUSTOM). */
#include "Uds29_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDS29_PKI_OK = 0, UDS29_PKI_PARSE, UDS29_PKI_EXPIRED, UDS29_PKI_CHAIN,
    UDS29_PKI_REVOKED,          /* CRL or serial blacklist */
    UDS29_PKI_POLICY,           /* key usage / EKU / algorithm policy */
    UDS29_PKI_TIME_UNTRUSTED    /* no trusted time (core only, never returned by a backend) */
} Uds29_PkiResult;
/* verify_peer_cert `at`: skip the validity-period checks (certificates and CRLs) altogether. */
#define UDS29_AT_SKIP_VALIDITY INT64_MIN

/* An "identity" is an opaque backend handle holding the trust anchor, our certificate and our private key
   (for an HSM: key handles). All lengths are bounded by the caller's buffers; never write past a capacity. */
typedef struct {
    void* ctx;  /* passed back as first argument of every call */
    /* Loads root CA, cert and key, checks key matches cert and cert chains to the root.
       cfg->mode is always UDS29_PKI_USER here (SAMPLE is resolved to file paths by the caller).
       Writes our cert (DER) to cert_der/cert_len. Returns the handle, NULL on any failure (incl. cert > cap). */
    void* (*load_identity)(void* ctx, const Uds29_PkiConfigType* cfg, uint8_t* cert_der, uint16_t cap, uint16_t* cert_len);
    void  (*free_identity)(void* ctx, void* id);
    /* Chain to the identity's root (through the configured intermediates; CRL-checked when CRLs are configured) +
       validity period. at = 0: now, UDS29_AT_SKIP_VALIDITY: no date checks, else unix time to judge validity at.
       Revoked by CRL -> UDS29_PKI_REVOKED. */
    Uds29_PkiResult (*verify_peer_cert)(void* ctx, void* id, const uint8_t* der, uint16_t len, int64_t at);
    /* Signs with the identity's key. E_NOT_OK if the signature does not fit sig_cap. */
    Std_ReturnType (*sign)(void* ctx, void* id, const uint8_t* data, uint16_t len,
                           uint8_t* sig, uint16_t sig_cap, uint16_t* sig_len);
    /* E_OK iff sig is valid over data for the public key of cert_der. */
    Std_ReturnType (*verify)(void* ctx, const uint8_t* cert_der, uint16_t cert_len,
                             const uint8_t* data, uint16_t len, const uint8_t* sig, uint16_t sig_len);
    Std_ReturnType (*random)(void* ctx, uint8_t* out, uint16_t n);
    /* OPTIONAL (NULL = not supported; certificate-extension based access control then reads nothing).
       Finds the X.509 v3 extension with OID oid_der (full DER: 06 len ...) in cert_der and writes its extnValue
       content (the DER inside the OCTET STRING) to out. E_NOT_OK if absent, malformed or larger than cap. */
    Std_ReturnType (*get_extension)(void* ctx, const uint8_t* cert_der, uint16_t cert_len,
                                    const uint8_t* oid_der, uint8_t oid_len, uint8_t* out, uint16_t cap, uint16_t* out_len);
    /* OPTIONAL (NULL = not supported; proof-of-ownership formats with certificate hashes then fail). SHA-256 of data. */
    Std_ReturnType (*sha256)(void* ctx, const uint8_t* data, uint16_t len, uint8_t out[32]);
} Uds29_CryptoOpsType;

/* Copies *ops (all function pointers required, else E_PARAM_POINTER). NULL restores the built-in backend.
   Call before Uds29_SetPki / loading any identity: handles belong to the backend that created them. */
Std_ReturnType             Uds29_SetCryptoOps(const Uds29_CryptoOpsType* ops);
const Uds29_CryptoOpsType* Uds29_GetCryptoOps(void);

/* Dispatchers used by the core. LoadIdentity resolves UDS29_PKI_SAMPLE to certs/sample/<sample_role>_*.pem
   (sample_role "tester" or "ecu"; only when built with UDS29_SAMPLE_DIR). */
void*           Uds29_Crypto_LoadIdentity(const Uds29_PkiConfigType* cfg, const char* sample_role,
                                          uint8_t* cert_der, uint16_t cap, uint16_t* cert_len);
void            Uds29_Crypto_FreeIdentity(void* id);
Uds29_PkiResult Uds29_Crypto_VerifyPeer(void* id, const uint8_t* der, uint16_t len, int64_t at);
Std_ReturnType  Uds29_Crypto_Sign(void* id, const uint8_t* data, uint16_t len, uint8_t* sig, uint16_t sig_cap, uint16_t* sig_len);
Std_ReturnType  Uds29_Crypto_Verify(const uint8_t* cert_der, uint16_t cert_len, const uint8_t* data, uint16_t len,
                                    const uint8_t* sig, uint16_t sig_len);
Std_ReturnType  Uds29_Crypto_Random(uint8_t* out, uint16_t n);
Std_ReturnType  Uds29_Crypto_GetExtension(const uint8_t* cert_der, uint16_t cert_len, const uint8_t* oid_der, uint8_t oid_len,
                                          uint8_t* out, uint16_t cap, uint16_t* out_len); /* E_NOT_OK if unsupported */

Std_ReturnType  Uds29_Crypto_Sha256(const uint8_t* data, uint16_t len, uint8_t out[32]); /* E_NOT_OK if unsupported */

/* Provided by the selected backend (not built for UDS29_CRYPTO=CUSTOM). */
const Uds29_CryptoOpsType* Uds29_Crypto_BuiltinOps(void);

#ifdef __cplusplus
}
#endif
