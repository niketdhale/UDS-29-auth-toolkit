/* OpenSSL (libcrypto) backend: ECDSA P-256/SHA-256 or Ed25519, by key type. Identities are heap-allocated. */
#include "Uds29_Crypto.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>

typedef struct { X509* root; X509* cert; EVP_PKEY* key; } Ident;

static X509* ReadCert(const char* path, Uds29_PkiFormatType f) {
    BIO* b = BIO_new_file(path, "rb");
    if (!b) return NULL;
    X509* x = f == UDS29_PKI_FORMAT_PEM ? PEM_read_bio_X509(b, NULL, NULL, NULL) : d2i_X509_bio(b, NULL);
    BIO_free_all(b);
    return x;
}

static EVP_PKEY* ReadKey(const char* path, Uds29_PkiFormatType f) {
    BIO* b = BIO_new_file(path, "rb");
    if (!b) return NULL;
    EVP_PKEY* k = f == UDS29_PKI_FORMAT_PEM ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : d2i_PrivateKey_bio(b, NULL);
    BIO_free_all(b);
    return k;
}

static X509* ParseDer(const uint8_t* der, uint16_t len) {
    const unsigned char* p = der;
    return len ? d2i_X509(NULL, &p, (long)len) : NULL;
}

static const EVP_MD* MdFor(EVP_PKEY* k) { return EVP_PKEY_id(k) == EVP_PKEY_ED25519 ? NULL : EVP_sha256(); }

static void FreeIdentity(void* ctx, void* h) {
    (void)ctx;
    Ident* id = h;
    if (!id) return;
    X509_free(id->root); X509_free(id->cert); EVP_PKEY_free(id->key);
    free(id);
}

static Uds29_PkiResult VerifyPeer(void* ctx, void* h, const uint8_t* der, uint16_t len, int64_t at) {
    (void)ctx;
    Ident* id = h;
    X509* c = ParseDer(der, len);
    if (!c) return UDS29_PKI_PARSE;
    Uds29_PkiResult res = UDS29_PKI_CHAIN;
    X509_STORE* st = X509_STORE_new();
    X509_STORE_CTX* sc = X509_STORE_CTX_new();
    if (id->root && st && sc && X509_STORE_add_cert(st, id->root) == 1 && X509_STORE_CTX_init(sc, st, c, NULL) == 1) {
        if (at) X509_STORE_CTX_set_time(sc, 0, (time_t)at);
        if (X509_verify_cert(sc) == 1) res = UDS29_PKI_OK;
        else {
            int e = X509_STORE_CTX_get_error(sc);
            if (e == X509_V_ERR_CERT_HAS_EXPIRED || e == X509_V_ERR_CERT_NOT_YET_VALID) res = UDS29_PKI_EXPIRED;
        }
    }
    X509_STORE_CTX_free(sc); X509_STORE_free(st); X509_free(c);
    return res;
}

static void* LoadIdentity(void* ctx, const Uds29_PkiConfigType* cfg, uint8_t* cert_der, uint16_t cap, uint16_t* cert_len) {
    Ident* id = calloc(1, sizeof *id);
    if (!id) return NULL;
    id->root = ReadCert(cfg->root_ca_path, cfg->format);
    id->cert = ReadCert(cfg->cert_path, cfg->format);
    id->key  = ReadKey(cfg->key_path, cfg->format);
    if (!id->root || !id->cert || !id->key || X509_check_private_key(id->cert, id->key) != 1) goto fail;
    unsigned char* der = NULL;
    int len = i2d_X509(id->cert, &der);
    if (len <= 0) goto fail;
    if (len > cap) { OPENSSL_free(der); goto fail; }
    memcpy(cert_der, der, (size_t)len);
    OPENSSL_free(der);
    *cert_len = (uint16_t)len;
    if (VerifyPeer(ctx, id, cert_der, *cert_len, 0) != UDS29_PKI_OK) goto fail;
    return id;
fail:
    FreeIdentity(ctx, id);
    return NULL;
}

static Std_ReturnType Sign(void* ctx, void* h, const uint8_t* data, uint16_t len, uint8_t* sig, uint16_t cap, uint16_t* sig_len) {
    (void)ctx;
    Ident* id = h;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    uint8_t tmp[256]; /* ECDSA P-256 DER <= 72, Ed25519 = 64 */
    size_t n = sizeof tmp;
    Std_ReturnType r = E_NOT_OK;
    if (c && EVP_DigestSignInit(c, NULL, MdFor(id->key), NULL, id->key) == 1 &&
        EVP_DigestSign(c, tmp, &n, data, len) == 1 && n <= cap) {
        memcpy(sig, tmp, n);
        *sig_len = (uint16_t)n;
        r = E_OK;
    }
    EVP_MD_CTX_free(c);
    return r;
}

static Std_ReturnType Verify(void* ctx, const uint8_t* cert_der, uint16_t cert_len, const uint8_t* data, uint16_t len,
                             const uint8_t* sig, uint16_t sig_len) {
    (void)ctx;
    X509* c = ParseDer(cert_der, cert_len);
    EVP_PKEY* k = c ? X509_get0_pubkey(c) : NULL;
    EVP_MD_CTX* m = EVP_MD_CTX_new();
    Std_ReturnType r = (k && m && sig_len && EVP_DigestVerifyInit(m, NULL, MdFor(k), NULL, k) == 1 &&
                        EVP_DigestVerify(m, sig, sig_len, data, len) == 1) ? E_OK : E_NOT_OK;
    EVP_MD_CTX_free(m);
    X509_free(c);
    return r;
}

static Std_ReturnType Random(void* ctx, uint8_t* out, uint16_t n) {
    (void)ctx;
    return (n == 0 || RAND_bytes(out, n) == 1) ? E_OK : E_NOT_OK;
}

static Std_ReturnType GetExtension(void* ctx, const uint8_t* cert_der, uint16_t cert_len, const uint8_t* oid, uint8_t oid_len,
                                   uint8_t* out, uint16_t cap, uint16_t* out_len) {
    (void)ctx;
    X509* c = ParseDer(cert_der, cert_len);
    const unsigned char* p = oid;
    ASN1_OBJECT* o = c ? d2i_ASN1_OBJECT(NULL, &p, oid_len) : NULL;
    int i = o ? X509_get_ext_by_OBJ(c, o, -1) : -1;
    Std_ReturnType r = E_NOT_OK;
    if (i >= 0) {
        const ASN1_OCTET_STRING* d = X509_EXTENSION_get_data(X509_get_ext(c, i));
        if (d && d->length >= 0 && (size_t)d->length <= cap) {
            memcpy(out, d->data, (size_t)d->length);
            *out_len = (uint16_t)d->length;
            r = E_OK;
        }
    }
    ASN1_OBJECT_free(o);
    X509_free(c);
    return r;
}

const Uds29_CryptoOpsType* Uds29_Crypto_BuiltinOps(void) {
    static const Uds29_CryptoOpsType ops = {NULL, LoadIdentity, FreeIdentity, VerifyPeer, Sign, Verify, Random, GetExtension};
    return &ops;
}
