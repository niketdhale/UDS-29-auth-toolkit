#include "Uds29_Crypto.h"
#include <stdio.h>
#include <string.h>

static Uds29_CryptoOpsType g_ops;
static bool g_custom;

const Uds29_CryptoOpsType* Uds29_GetCryptoOps(void) {
    if (g_custom) return &g_ops;
#ifdef UDS29_CRYPTO_CUSTOM
    return NULL; /* no built-in backend: Uds29_SetCryptoOps is mandatory */
#else
    return Uds29_Crypto_BuiltinOps();
#endif
}

Std_ReturnType Uds29_SetCryptoOps(const Uds29_CryptoOpsType* ops) {
    if (!ops) { g_custom = false; return E_OK; }
    if (!ops->load_identity || !ops->free_identity || !ops->verify_peer_cert || !ops->sign || !ops->verify || !ops->random)
        return E_PARAM_POINTER;
    g_ops = *ops;
    g_custom = true;
    return E_OK;
}

void* Uds29_Crypto_LoadIdentity(const Uds29_PkiConfigType* cfg, const char* role, uint8_t* cert_der,
                                uint16_t cap, uint16_t* cert_len) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !cfg || !cert_der || !cert_len) return NULL;
    Uds29_PkiConfigType c = *cfg;
    char root[256], cert[256], key[256];
    if (cfg->mode == UDS29_PKI_SAMPLE) {
#ifdef UDS29_SAMPLE_DIR
        if (!role ||
            snprintf(root, sizeof root, "%s/root_ca.pem", UDS29_SAMPLE_DIR) >= (int)sizeof root ||
            snprintf(cert, sizeof cert, "%s/%s_cert.pem", UDS29_SAMPLE_DIR, role) >= (int)sizeof cert ||
            snprintf(key, sizeof key, "%s/%s_key.pem", UDS29_SAMPLE_DIR, role) >= (int)sizeof key)
            return NULL;
        c.mode = UDS29_PKI_USER; c.format = UDS29_PKI_FORMAT_PEM;
        c.root_ca_path = root; c.cert_path = cert; c.key_path = key;
#else
        (void)role; (void)root; (void)cert; (void)key;
        return NULL; /* no sample directory on this build */
#endif
    } else if (!c.root_ca_path || !c.cert_path || !c.key_path) {
        return NULL;
    }
    return o->load_identity(o->ctx, &c, cert_der, cap, cert_len);
}

void Uds29_Crypto_FreeIdentity(void* id) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (o && id) o->free_identity(o->ctx, id);
}

Uds29_PkiResult Uds29_Crypto_VerifyPeer(void* id, const uint8_t* der, uint16_t len, int64_t at) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !id || !der) return UDS29_PKI_PARSE;
    return o->verify_peer_cert(o->ctx, id, der, len, at);
}

Std_ReturnType Uds29_Crypto_Sign(void* id, const uint8_t* data, uint16_t len, uint8_t* sig, uint16_t sig_cap, uint16_t* sig_len) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !id || !data || !sig || !sig_len) return E_NOT_OK;
    *sig_len = 0;
    return o->sign(o->ctx, id, data, len, sig, sig_cap, sig_len);
}

Std_ReturnType Uds29_Crypto_Verify(const uint8_t* cert_der, uint16_t cert_len, const uint8_t* data, uint16_t len,
                                   const uint8_t* sig, uint16_t sig_len) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !cert_der || !data || !sig || sig_len == 0) return E_NOT_OK;
    return o->verify(o->ctx, cert_der, cert_len, data, len, sig, sig_len);
}

Std_ReturnType Uds29_Crypto_Random(uint8_t* out, uint16_t n) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || (n && !out)) return E_NOT_OK;
    return o->random(o->ctx, out, n);
}

Std_ReturnType Uds29_Crypto_GetExtension(const uint8_t* cert_der, uint16_t cert_len, const uint8_t* oid_der, uint8_t oid_len,
                                         uint8_t* out, uint16_t cap, uint16_t* out_len) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !o->get_extension || !cert_der || !oid_der || !out || !out_len) return E_NOT_OK;
    *out_len = 0;
    return o->get_extension(o->ctx, cert_der, cert_len, oid_der, oid_len, out, cap, out_len);
}

Std_ReturnType Uds29_Crypto_Sha256(const uint8_t* data, uint16_t len, uint8_t out[32]) {
    const Uds29_CryptoOpsType* o = Uds29_GetCryptoOps();
    if (!o || !o->sha256 || !out || (len && !data)) return E_NOT_OK;
    return o->sha256(o->ctx, data, len, out);
}
