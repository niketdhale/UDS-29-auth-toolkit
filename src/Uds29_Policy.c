#include "Uds29_Policy.h"
#include "Uds29_Der.h"
#include <time.h>

static bool Policy(const Uds29_CertPolicy* p, const uint8_t* der, uint16_t len) {
    Uds29_DerCert c;
    unsigned ku;
    if (!p->require_key_usage_digital_signature && !p->required_eku_oid && !p->allowed_key_types && !p->allowed_sig_algs) return true;
    if (!Uds29_Der_ParseCert(der, len, &c)) return false;
    if (p->require_key_usage_digital_signature && !(Uds29_Der_KeyUsage(&c, &ku) && (ku & 0x8000u))) return false;
    if (p->allowed_key_types && !(Uds29_Der_KeyType(&c) & p->allowed_key_types)) return false;
    if (p->allowed_sig_algs && !(Uds29_Der_SigAlg(&c) & p->allowed_sig_algs)) return false;
    if (p->required_eku_oid) {
        const uint8_t *list, *o;
        size_t n, ol;
        uint8_t t;
        bool found = false;
        if (p->required_eku_oid_len < 3 || p->required_eku_oid[0] != 0x06 || p->required_eku_oid[1] != p->required_eku_oid_len - 2u ||
            !Uds29_Der_Eku(&c, &list, &n))
            return false;
        for (const uint8_t* q = list; Uds29_Der_Tlv(&q, list + n, &t, &o, &ol); )
            found |= t == 0x06 && ol == p->required_eku_oid_len - 2u && !memcmp(o, p->required_eku_oid + 2, ol);
        if (!found) return false;
    }
    return true;
}

static bool Revoked(const Uds29_Verifier* v, const uint8_t* der, uint16_t len) {
    Uds29_DerCert c;
    if (!v->n_revoked || !v->revoked || !Uds29_Der_ParseCert(der, len, &c)) return false;
    for (uint16_t i = 0; i < v->n_revoked; i++)
        if (v->revoked[i].data && Uds29_Der_SerialEq(c.serial, c.serial_len, v->revoked[i].data, v->revoked[i].len)) return true;
    return false;
}

Uds29_PkiResult Uds29_Verifier_Check(Uds29_Verifier* v, void* ident, const uint8_t* der, uint16_t len,
                                     int64_t at_override, bool* skipped) {
    int64_t at = at_override;
    *skipped = false;
    if (!at) {
        if (v->policy.time_mode == UDS29_TIME_SKIP_WITH_EVENT) { at = UDS29_AT_SKIP_VALIDITY; *skipped = true; }
        else {
            int64_t t = 0;
            if (v->policy.time_mode == UDS29_TIME_HOOK) {
                if (!v->time_fn || v->time_fn(&t, v->time_ctx) != E_OK) return UDS29_PKI_TIME_UNTRUSTED;
            } else t = (int64_t)time(NULL);
            if (t <= 0) return UDS29_PKI_TIME_UNTRUSTED;
            if (v->policy.time_monotonic_guard) {
                if (t + (int64_t)v->policy.time_backstep_tolerance_s < v->max_time) return UDS29_PKI_TIME_UNTRUSTED;
                if (t > v->max_time) v->max_time = t;
            }
            at = t;
        }
    }
    Uds29_PkiResult r = Uds29_Crypto_VerifyPeer(ident, der, len, at);
    if (r != UDS29_PKI_OK) return r;
    if (Revoked(v, der, len)) return UDS29_PKI_REVOKED;
    return Policy(&v->policy, der, len) ? UDS29_PKI_OK : UDS29_PKI_POLICY;
}

static bool Put(uint8_t* out, uint16_t cap, uint16_t* n, const uint8_t* p, uint16_t l) {
    if (l > cap - *n) return false;
    if (l) memcpy(out + *n, p, l);
    *n = (uint16_t)(*n + l);
    return true;
}

bool Uds29_Pown_Build(const Uds29_PownFormat* f, const Uds29_PownIn* in, uint8_t* out, uint16_t cap, uint16_t* n) {
    uint8_t h[32];
    *n = 0;
    if (f->count == 0) return Put(out, cap, n, in->raw, in->raw_len);
    if (f->count > UDS29_POWN_MAX_ELEMENTS) return false;
    for (uint8_t i = 0; i < f->count; i++) {
        bool ok;
        switch (f->elements[i]) {
        case UDS29_POWN_SERVER_CHALLENGE: ok = Put(out, cap, n, in->server_ch, in->server_len); break;
        case UDS29_POWN_CLIENT_CHALLENGE: ok = !in->bidi || Put(out, cap, n, in->client_ch, in->client_len); break;
        case UDS29_POWN_ADDITIONAL_PARAM: ok = Put(out, cap, n, &in->comm, 1); break;
        case UDS29_POWN_PEER_CERT_HASH_SHA256:
            ok = in->peer_len && Uds29_Crypto_Sha256(in->peer_cert, in->peer_len, h) == E_OK && Put(out, cap, n, h, 32); break;
        case UDS29_POWN_OWN_CERT_HASH_SHA256:
            ok = in->own_len && Uds29_Crypto_Sha256(in->own_cert, in->own_len, h) == E_OK && Put(out, cap, n, h, 32); break;
        default: ok = false;
        }
        if (!ok) return false;
    }
    return true;
}
