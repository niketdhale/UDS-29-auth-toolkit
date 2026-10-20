#pragma once
#include "Uds29_Types.h"
#include "Uds29_Codec.h"
#include <ctime>
#include <memory>

typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;

enum Uds29_PkiResult { UDS29_PKI_OK = 0, UDS29_PKI_PARSE, UDS29_PKI_EXPIRED, UDS29_PKI_CHAIN };

/* Local identity (cert + key) plus trust anchor, backed by OpenSSL libcrypto. */
class Uds29Pki {
public:
    Uds29Pki();
    ~Uds29Pki();
    Uds29Pki(const Uds29Pki&) = delete;
    Uds29Pki& operator=(const Uds29Pki&) = delete;

    /* Loads root CA, cert, key and checks key matches cert and cert chains to root.
       SAMPLE mode loads certs/sample/<sample_role>_{cert,key}.pem ("tester" or "ecu"). */
    bool Load(const Uds29_PkiConfigType& cfg, const char* sample_role = "tester");

    const Uds29_Bytes& CertDer() const { return cert_der_; }

    /* Verify chain to the root CA and validity period (at = 0: now). */
    Uds29_PkiResult VerifyPeer(const Uds29_Bytes& cert_der, time_t at = 0) const;

    /* Signs with the local key: ECDSA P-256/SHA-256 or Ed25519 (by key type). */
    bool Sign(const Uds29_Bytes& data, Uds29_Bytes& sig) const;
    /* Verifies sig over data with the public key in cert_der. */
    static bool Verify(const Uds29_Bytes& cert_der, const Uds29_Bytes& data, const Uds29_Bytes& sig);

    static Uds29_Bytes Random(size_t n);

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
    Uds29_Bytes cert_der_;
};
