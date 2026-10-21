/* mbedTLS 3.x backend: X.509 parse/verify, ECDSA (P-256 certs/keys) with SHA-256, CTR_DRBG random.
   NOT SUPPORTED: Ed25519 (mbedTLS has no Ed25519) - certificates or keys of that type fail to load
   (load_identity returns NULL) and sign/verify return E_NOT_OK.
   Notes for embedded targets: the DRBG is seeded from mbedtls_entropy (provide an entropy source via
   MBEDTLS_ENTROPY_HARDWARE_ALT / mbedtls_platform), mbedTLS allocates while parsing certificates (use
   MBEDTLS_MEMORY_BUFFER_ALLOC_C for a static heap), and identity files are read with stdio (a port without
   a file system registers its own ops with Uds29_SetCryptoOps). Identities come from a static pool. */
#include "Uds29_Crypto.h"
#include "Uds29_Cfg.h"
#include "Uds29_Os.h"
#include "../Uds29_Der.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <string.h>

#define MAX_IDENTITIES 4

typedef struct {
    bool used;
    mbedtls_x509_crt root, cert, inter;
    mbedtls_x509_crl crl;
    mbedtls_pk_context key;
} Ident;

static Ident g_ids[MAX_IDENTITIES];
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static bool g_seeded;

/* f_rng for mbedTLS; seeds the DRBG on first use. Serialised by the OS lock (the DRBG is not thread safe). */
static int Rng(void* p, unsigned char* out, size_t n) {
    (void)p;
    int r = -1;
    Uds29_Os_Lock();
    if (!g_seeded) {
        mbedtls_entropy_init(&g_entropy);
        mbedtls_ctr_drbg_init(&g_drbg);
        if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy, (const unsigned char*)"uds29", 5) == 0)
            g_seeded = true;
    }
    if (g_seeded) r = mbedtls_ctr_drbg_random(&g_drbg, out, n);
    Uds29_Os_Unlock();
    return r;
}

/* Reads a whole file plus a NUL terminator; false if missing or larger than cap-1. */
static bool ReadFile(const char* path, uint8_t* buf, size_t cap, size_t* n) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    *n = fread(buf, 1, cap - 1, f);
    bool ok = !ferror(f) && fgetc(f) == EOF;
    fclose(f);
    buf[*n] = 0;
    return ok && *n > 0;
}

static bool ParseCert(mbedtls_x509_crt* c, const char* path, Uds29_PkiFormatType fmt) {
    uint8_t b[2 * UDS29_MAX_CERT_LEN + 1];
    size_t n;
    if (!ReadFile(path, b, sizeof b, &n)) return false;
    if (fmt == UDS29_PKI_FORMAT_DER) return mbedtls_x509_crt_parse_der(c, b, n) == 0;
    return strstr((char*)b, "-----BEGIN CERTIFICATE-----") && mbedtls_x509_crt_parse(c, b, n + 1) == 0;
}

static bool ParseCrl(mbedtls_x509_crl* c, const char* path, Uds29_PkiFormatType fmt) {
    uint8_t b[4097]; /* ponytail: CRL files up to 4 KiB per file; raise for bigger lists */
    size_t n;
    if (!ReadFile(path, b, sizeof b, &n)) return false;
    if (fmt == UDS29_PKI_FORMAT_DER) return mbedtls_x509_crl_parse_der(c, b, n) == 0;
    return strstr((char*)b, "-----BEGIN X509 CRL-----") && mbedtls_x509_crl_parse(c, b, n + 1) == 0;
}

static bool ParseKey(mbedtls_pk_context* k, const char* path, Uds29_PkiFormatType fmt) {
    uint8_t b[2 * UDS29_MAX_CERT_LEN + 1];
    size_t n;
    if (!ReadFile(path, b, sizeof b, &n)) return false;
    if (fmt == UDS29_PKI_FORMAT_PEM && !strstr((char*)b, "-----BEGIN")) return false;
    return mbedtls_pk_parse_key(k, b, fmt == UDS29_PKI_FORMAT_PEM ? n + 1 : n, NULL, 0, Rng, NULL) == 0;
}

/* Seconds since 1970 -> broken-down UTC without libc time functions (Hinnant's civil_from_days). */
static void FromUnix(int64_t t, mbedtls_x509_time* o) {
    int64_t days = t / 86400, s = t % 86400;
    if (s < 0) { s += 86400; days--; }
    days += 719468;
    int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    int64_t doe = days - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    o->day = (int)(doy - (153 * mp + 2) / 5 + 1);
    o->mon = (int)(mp < 10 ? mp + 3 : mp - 9);
    o->year = (int)(yoe + era * 400 + (o->mon <= 2));
    o->hour = (int)(s / 3600); o->min = (int)(s % 3600 / 60); o->sec = (int)(s % 60);
}

static int Cmp(const mbedtls_x509_time* a, const mbedtls_x509_time* b) {
    int x[6] = {a->year, a->mon, a->day, a->hour, a->min, a->sec}, y[6] = {b->year, b->mon, b->day, b->hour, b->min, b->sec};
    for (int i = 0; i < 6; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}

typedef struct { int64_t at; mbedtls_x509_crl* crls; } TimeCtx;

/* Re-judges certificate and CRL freshness at the time given in tc->at (the time override), or not at all (skip). */
static int VerifyAt(void* p, mbedtls_x509_crt* c, int depth, uint32_t* flags) {
    (void)depth;
    const TimeCtx* tc = p;
    const uint32_t time_flags = MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE |
                                MBEDTLS_X509_BADCRL_EXPIRED | MBEDTLS_X509_BADCRL_FUTURE;
    *flags &= ~time_flags;
    if (tc->at == UDS29_AT_SKIP_VALIDITY) return 0;
    mbedtls_x509_time now;
    FromUnix(tc->at, &now);
    if (Cmp(&now, &c->valid_from) < 0) *flags |= MBEDTLS_X509_BADCERT_FUTURE;
    if (Cmp(&now, &c->valid_to) > 0) *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
    for (const mbedtls_x509_crl* l = tc->crls; l && l->version; l = l->next) {
        if (l->issuer_raw.len != c->issuer_raw.len || memcmp(l->issuer_raw.p, c->issuer_raw.p, l->issuer_raw.len)) continue;
        if (Cmp(&now, &l->this_update) < 0) *flags |= MBEDTLS_X509_BADCRL_FUTURE;
        if (l->next_update.year && Cmp(&now, &l->next_update) > 0) *flags |= MBEDTLS_X509_BADCRL_EXPIRED;
    }
    return 0;
}

static void FreeIdentity(void* ctx, void* h) {
    (void)ctx;
    Ident* id = h;
    if (!id) return;
    Uds29_Os_Lock();
    mbedtls_x509_crt_free(&id->root); mbedtls_x509_crt_free(&id->cert); mbedtls_x509_crt_free(&id->inter);
    mbedtls_x509_crl_free(&id->crl); mbedtls_pk_free(&id->key);
    id->used = false;
    Uds29_Os_Unlock();
}

static Uds29_PkiResult VerifyPeer(void* ctx, void* h, const uint8_t* der, uint16_t len, int64_t at) {
    (void)ctx;
    Ident* id = h;
    mbedtls_x509_crt c;
    mbedtls_x509_crt_init(&c);
    Uds29_PkiResult res = UDS29_PKI_PARSE;
    if (len && mbedtls_x509_crt_parse_der(&c, der, len) == 0) {
        uint32_t flags = 0;
        TimeCtx tc = {at, id->crl.version ? &id->crl : NULL};
        bool ok = true;
        /* the intermediates follow the leaf in the chain: untrusted, only chained through */
        for (const mbedtls_x509_crt* i = id->inter.version ? &id->inter : NULL; ok && i; i = i->next)
            ok = mbedtls_x509_crt_parse_der(&c, i->raw.p, i->raw.len) == 0;
        int r = ok ? mbedtls_x509_crt_verify(&c, &id->root, tc.crls, NULL, &flags, at ? VerifyAt : NULL, &tc) : -1;
        if (r == 0) res = UDS29_PKI_OK;
        else if ((flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) || !ok) res = UDS29_PKI_CHAIN;
        else if (flags & MBEDTLS_X509_BADCERT_REVOKED) res = UDS29_PKI_REVOKED;
        else if (flags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)) res = UDS29_PKI_EXPIRED;
        else res = UDS29_PKI_CHAIN;
    }
    mbedtls_x509_crt_free(&c);
    return res;
}

static void* LoadIdentity(void* ctx, const Uds29_PkiConfigType* cfg, uint8_t* cert_der, uint16_t cap, uint16_t* cert_len) {
    Ident* id = NULL;
    Uds29_Os_Lock();
    for (int i = 0; i < MAX_IDENTITIES && !id; i++) if (!g_ids[i].used) id = &g_ids[i];
    if (id) {
        id->used = true;
        mbedtls_x509_crt_init(&id->root); mbedtls_x509_crt_init(&id->cert); mbedtls_x509_crt_init(&id->inter);
        mbedtls_x509_crl_init(&id->crl); mbedtls_pk_init(&id->key);
    }
    Uds29_Os_Unlock();
    if (!id) return NULL;
    bool ok = ParseCert(&id->root, cfg->root_ca_path, cfg->format) && ParseCert(&id->cert, cfg->cert_path, cfg->format);
    for (unsigned i = 0; ok && i < UDS29_MAX_INTERMEDIATES && cfg->intermediate_paths[i]; i++)
        ok = ParseCert(&id->inter, cfg->intermediate_paths[i], cfg->format);
    for (unsigned i = 0; ok && i < UDS29_MAX_CRLS && cfg->crl_paths[i]; i++)
        ok = ParseCrl(&id->crl, cfg->crl_paths[i], cfg->format);
    if (ok &&
        ParseKey(&id->key, cfg->key_path, cfg->format) && mbedtls_pk_can_do(&id->key, MBEDTLS_PK_ECDSA) &&
        mbedtls_pk_check_pair(&id->cert.pk, &id->key, Rng, NULL) == 0 &&
        id->cert.raw.len <= cap && id->cert.raw.len <= 0xFFFFu) {
        memcpy(cert_der, id->cert.raw.p, id->cert.raw.len);
        *cert_len = (uint16_t)id->cert.raw.len;
        if (VerifyPeer(ctx, id, cert_der, *cert_len, cfg->skip_validity_check ? UDS29_AT_SKIP_VALIDITY : 0) == UDS29_PKI_OK) return id;
    }
    FreeIdentity(ctx, id);
    return NULL;
}

static Std_ReturnType Sign(void* ctx, void* h, const uint8_t* data, uint16_t len, uint8_t* sig, uint16_t cap, uint16_t* sig_len) {
    (void)ctx;
    Ident* id = h;
    uint8_t hash[32], tmp[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t n = 0;
    if (!mbedtls_pk_can_do(&id->key, MBEDTLS_PK_ECDSA) ||
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, len, hash) != 0 ||
        mbedtls_pk_sign(&id->key, MBEDTLS_MD_SHA256, hash, sizeof hash, tmp, sizeof tmp, &n, Rng, NULL) != 0 || n > cap)
        return E_NOT_OK;
    memcpy(sig, tmp, n);
    *sig_len = (uint16_t)n;
    return E_OK;
}

static Std_ReturnType Verify(void* ctx, const uint8_t* cert_der, uint16_t cert_len, const uint8_t* data, uint16_t len,
                             const uint8_t* sig, uint16_t sig_len) {
    (void)ctx;
    mbedtls_x509_crt c;
    uint8_t hash[32];
    mbedtls_x509_crt_init(&c);
    Std_ReturnType r = E_NOT_OK;
    if (cert_len && sig_len && mbedtls_x509_crt_parse_der(&c, cert_der, cert_len) == 0 &&
        mbedtls_pk_can_do(&c.pk, MBEDTLS_PK_ECDSA) &&
        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, len, hash) == 0 &&
        mbedtls_pk_verify(&c.pk, MBEDTLS_MD_SHA256, hash, sizeof hash, sig, sig_len) == 0)
        r = E_OK;
    mbedtls_x509_crt_free(&c);
    return r;
}

static Std_ReturnType Random(void* ctx, uint8_t* out, uint16_t n) {
    (void)ctx;
    return Rng(NULL, out, n) == 0 ? E_OK : E_NOT_OK;
}

/* crt.v3_ext.p points at the Extensions SEQUENCE; parse_der keeps its own copy of the bytes. */
static Std_ReturnType GetExtension(void* ctx, const uint8_t* cert_der, uint16_t cert_len, const uint8_t* oid, uint8_t oid_len,
                                   uint8_t* out, uint16_t cap, uint16_t* out_len) {
    (void)ctx;
    mbedtls_x509_crt c;
    mbedtls_x509_crt_init(&c);
    Std_ReturnType r = E_NOT_OK;
    const uint8_t* v;
    size_t vl;
    if (oid_len > 2 && oid[0] == 0x06 && oid[1] == oid_len - 2u && cert_len &&
        mbedtls_x509_crt_parse_der(&c, cert_der, cert_len) == 0 && c.v3_ext.p &&
        Uds29_Der_FindExt(c.v3_ext.p, c.v3_ext.len, oid + 2, oid_len - 2u, &v, &vl) && vl <= cap) {
        memcpy(out, v, vl);
        *out_len = (uint16_t)vl;
        r = E_OK;
    }
    mbedtls_x509_crt_free(&c);
    return r;
}

static Std_ReturnType Sha256(void* ctx, const uint8_t* data, uint16_t len, uint8_t out[32]) {
    (void)ctx;
    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, len, out) == 0 ? E_OK : E_NOT_OK;
}

const Uds29_CryptoOpsType* Uds29_Crypto_BuiltinOps(void) {
    static const Uds29_CryptoOpsType ops = {NULL, LoadIdentity, FreeIdentity, VerifyPeer, Sign, Verify, Random, GetExtension, Sha256};
    return &ops;
}
