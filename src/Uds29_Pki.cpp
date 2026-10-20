#include "Uds29_Pki.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <string>

#ifndef UDS29_SAMPLE_DIR
#error "UDS29_SAMPLE_DIR must point at certs/sample (set by CMake)"
#endif

namespace {
template <class T, void (*F)(T*)> struct Del { void operator()(T* p) const { F(p); } };
typedef std::unique_ptr<X509, Del<X509, X509_free>> X509P;
typedef std::unique_ptr<EVP_PKEY, Del<EVP_PKEY, EVP_PKEY_free>> KeyP;
typedef std::unique_ptr<BIO, Del<BIO, BIO_free_all>> BioP;

X509P ReadCert(const char* path, Uds29_PkiFormatType f) {
    BioP b(BIO_new_file(path, "rb"));
    if (!b) return nullptr;
    return X509P(f == UDS29_PKI_FORMAT_PEM ? PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr)
                                           : d2i_X509_bio(b.get(), nullptr));
}

KeyP ReadKey(const char* path, Uds29_PkiFormatType f) {
    BioP b(BIO_new_file(path, "rb"));
    if (!b) return nullptr;
    return KeyP(f == UDS29_PKI_FORMAT_PEM ? PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr)
                                          : d2i_PrivateKey_bio(b.get(), nullptr));
}

X509P ParseDer(const Uds29_Bytes& der) {
    const unsigned char* p = der.data();
    return X509P(der.empty() ? nullptr : d2i_X509(nullptr, &p, long(der.size())));
}

const EVP_MD* MdFor(EVP_PKEY* k) { return EVP_PKEY_id(k) == EVP_PKEY_ED25519 ? nullptr : EVP_sha256(); }
} // namespace

struct Uds29Pki::Impl {
    X509P root, cert;
    KeyP  key;
};

Uds29Pki::Uds29Pki() : p_(new Impl) {}
Uds29Pki::~Uds29Pki() = default;

bool Uds29Pki::Load(const Uds29_PkiConfigType& cfg, const char* sample_role) {
    std::string root, cert, key;
    Uds29_PkiFormatType fmt = cfg.format;
    if (cfg.mode == UDS29_PKI_SAMPLE) {
        std::string d = std::string(UDS29_SAMPLE_DIR) + "/";
        root = d + "root_ca.pem";
        cert = d + sample_role + "_cert.pem";
        key  = d + sample_role + "_key.pem";
        fmt  = UDS29_PKI_FORMAT_PEM;
    } else {
        if (!cfg.root_ca_path || !cfg.cert_path || !cfg.key_path) return false;
        root = cfg.root_ca_path; cert = cfg.cert_path; key = cfg.key_path;
    }
    Impl n;
    n.root = ReadCert(root.c_str(), fmt);
    n.cert = ReadCert(cert.c_str(), fmt);
    n.key  = ReadKey(key.c_str(), fmt);
    if (!n.root || !n.cert || !n.key || X509_check_private_key(n.cert.get(), n.key.get()) != 1) return false;

    unsigned char* der = nullptr;
    int len = i2d_X509(n.cert.get(), &der);
    if (len <= 0) return false;
    Uds29_Bytes cert_der(der, der + len);
    OPENSSL_free(der);

    *p_ = std::move(n);
    cert_der_ = std::move(cert_der);
    if (VerifyPeer(cert_der_) != UDS29_PKI_OK) { p_.reset(new Impl); cert_der_.clear(); return false; }
    return true;
}

Uds29_PkiResult Uds29Pki::VerifyPeer(const Uds29_Bytes& cert_der, time_t at) const {
    X509P c = ParseDer(cert_der);
    if (!c) return UDS29_PKI_PARSE;
    if (!p_->root) return UDS29_PKI_CHAIN;
    std::unique_ptr<X509_STORE, Del<X509_STORE, X509_STORE_free>> st(X509_STORE_new());
    std::unique_ptr<X509_STORE_CTX, Del<X509_STORE_CTX, X509_STORE_CTX_free>> ctx(X509_STORE_CTX_new());
    if (!st || !ctx || X509_STORE_add_cert(st.get(), p_->root.get()) != 1 ||
        X509_STORE_CTX_init(ctx.get(), st.get(), c.get(), nullptr) != 1)
        return UDS29_PKI_CHAIN;
    if (at) X509_STORE_CTX_set_time(ctx.get(), 0, at);
    if (X509_verify_cert(ctx.get()) == 1) return UDS29_PKI_OK;
    int e = X509_STORE_CTX_get_error(ctx.get());
    return (e == X509_V_ERR_CERT_HAS_EXPIRED || e == X509_V_ERR_CERT_NOT_YET_VALID) ? UDS29_PKI_EXPIRED
                                                                                  : UDS29_PKI_CHAIN;
}

bool Uds29Pki::Sign(const Uds29_Bytes& data, Uds29_Bytes& sig) const {
    if (!p_->key) return false;
    std::unique_ptr<EVP_MD_CTX, Del<EVP_MD_CTX, EVP_MD_CTX_free>> c(EVP_MD_CTX_new());
    size_t n = 0;
    if (!c || EVP_DigestSignInit(c.get(), nullptr, MdFor(p_->key.get()), nullptr, p_->key.get()) != 1 ||
        EVP_DigestSign(c.get(), nullptr, &n, data.data(), data.size()) != 1)
        return false;
    sig.resize(n);
    if (EVP_DigestSign(c.get(), sig.data(), &n, data.data(), data.size()) != 1) return false;
    sig.resize(n);
    return true;
}

bool Uds29Pki::Verify(const Uds29_Bytes& cert_der, const Uds29_Bytes& data, const Uds29_Bytes& sig) {
    X509P c = ParseDer(cert_der);
    EVP_PKEY* k = c ? X509_get0_pubkey(c.get()) : nullptr;
    std::unique_ptr<EVP_MD_CTX, Del<EVP_MD_CTX, EVP_MD_CTX_free>> m(EVP_MD_CTX_new());
    return k && m && !sig.empty() &&
           EVP_DigestVerifyInit(m.get(), nullptr, MdFor(k), nullptr, k) == 1 &&
           EVP_DigestVerify(m.get(), sig.data(), sig.size(), data.data(), data.size()) == 1;
}

Uds29_Bytes Uds29Pki::Random(size_t n) {
    Uds29_Bytes b(n);
    if (n && RAND_bytes(b.data(), int(n)) != 1) b.clear();
    return b;
}
