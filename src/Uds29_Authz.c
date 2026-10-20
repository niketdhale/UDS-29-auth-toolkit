/* Certificate profile interpreter: bounded DER decoding of roles / allow-lists. No heap, no recursion. */
#include "Uds29_Authz.h"
#include "Uds29_Crypto.h"
#include "Uds29_Der.h"
#include <string.h>

/* "1.3.6.1.4.1.99999.29.1" -> 06 len content. */
static bool OidFromDotted(const char* s, uint8_t* out, uint8_t cap, uint8_t* n) {
    uint32_t arc[16], v = 0;
    unsigned na = 0, digits = 0;
    for (;; s++) {
        if (*s >= '0' && *s <= '9') { v = v * 10 + (uint32_t)(*s - '0'); digits++; if (v > 0x0FFFFFFFu) return false; }
        else if ((*s == '.' || *s == 0) && digits && na < 16) { arc[na++] = v; v = 0; digits = 0; if (!*s) break; }
        else return false;
    }
    if (na < 2 || arc[0] > 2 || (arc[0] < 2 && arc[1] > 39)) return false;
    uint8_t body[30];
    unsigned k = 0;
    arc[1] += arc[0] * 40;
    for (unsigned i = 1; i < na; i++) {
        uint8_t tmp[5];
        unsigned t = 0;
        v = arc[i];
        do { tmp[t++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v);
        if (k + t > sizeof body) return false;
        while (t--) body[k++] = (uint8_t)(tmp[t] | (t ? 0x80 : 0));
    }
    if (k + 2u > cap) return false;
    out[0] = 0x06; out[1] = (uint8_t)k;
    memcpy(out + 2, body, k);
    *n = (uint8_t)(k + 2u);
    return true;
}

/* mask = v is a role mask to OR in (STRING_MAP on ROLE); else v is a role bit index / an identifier. */
static bool Add(Uds29_Authz* a, Uds29_AzKind k, uint32_t v, bool mask) {
    switch (k) {
    case UDS29_AZ_ROLE:
        if (mask) { a->roles |= v; return true; }
        if (v > 31) return false;
        a->roles |= 1u << v;
        return true;
    case UDS29_AZ_SERVICES:
        if (v > 0xFFu || a->n_services >= UDS29_MAX_ALLOW) return false;
        a->services[a->n_services++] = (uint8_t)v;
        return true;
    case UDS29_AZ_DIDS:
        if (v > 0xFFFFu || a->n_dids >= UDS29_MAX_ALLOW) return false;
        a->dids[a->n_dids++] = (uint16_t)v;
        return true;
    case UDS29_AZ_RIDS:
        if (v > 0xFFFFu || a->n_rids >= UDS29_MAX_ALLOW) return false;
        a->rids[a->n_rids++] = (uint16_t)v;
        return true;
    }
    return false;
}

/* Non-negative INTEGER content of at most 32 bits. */
static bool UInt(const uint8_t* v, size_t l, uint32_t* out) {
    if (l == 0 || (v[0] & 0x80)) return false;
    if (l > 1 && v[0] == 0) { v++; l--; }
    if (l > 4) return false;
    uint32_t x = 0;
    while (l--) x = (x << 8) | *v++;
    *out = x;
    return true;
}

Std_ReturnType Uds29_Authz_Decode(const Uds29_CertProfileItem* it, const uint8_t* value, uint16_t len, Uds29_Authz* out) {
    if (!it || !value || !out) return E_PARAM_POINTER;
    const uint8_t *p = value, *end = value + len, *v;
    uint8_t t;
    size_t l;
    uint32_t x;
    bool ext = it->source == UDS29_AZ_EXTENSION_OID;
    if (!ext && it->encoding != UDS29_AZ_STRING_MAP) return E_NOT_OK; /* OU / CN are strings */

    if (it->encoding == UDS29_AZ_STRING_MAP) {
        if (ext) {                                   /* DER string */
            if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || p != end || (t != 0x0C && t != 0x13 && t != 0x16)) return E_NOT_OK;
        } else { v = value; l = len; }
        for (unsigned i = 0; i < it->map_count; i++)
            if (strlen(it->map[i].str) == l && !memcmp(it->map[i].str, v, l) &&
                !Add(out, it->kind, it->map[i].value, it->kind == UDS29_AZ_ROLE)) return E_NOT_OK;
        return E_OK;
    }
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || p != end) return E_NOT_OK;
    switch (it->encoding) {
    case UDS29_AZ_BITSTRING_MASK: {
        if (t != 0x03 || l < 1 || v[0] > 7 || (l == 1 && v[0])) return E_NOT_OK;
        size_t bits = (l - 1) * 8 - v[0];
        for (size_t i = 0; i < bits; i++)
            if ((v[1 + i / 8] & (0x80u >> (i % 8))) && !Add(out, it->kind, (uint32_t)i, false)) return E_NOT_OK;
        return E_OK;
    }
    case UDS29_AZ_INTEGER_MASK:
        if (t != 0x02 || !UInt(v, l, &x)) return E_NOT_OK;
        for (unsigned i = 0; i < 32; i++)
            if ((x >> i) & 1u && !Add(out, it->kind, i, false)) return E_NOT_OK;
        return E_OK;
    case UDS29_AZ_OCTETS_ID8:
    case UDS29_AZ_OCTETS_ID16:
    case UDS29_AZ_OCTETS_ID32: {
        size_t w = it->encoding == UDS29_AZ_OCTETS_ID8 ? 1 : it->encoding == UDS29_AZ_OCTETS_ID16 ? 2 : 4;
        if (t != 0x04 || l % w) return E_NOT_OK;
        for (size_t i = 0; i < l; i += w) {
            x = 0;
            for (size_t j = 0; j < w; j++) x = (x << 8) | v[i + j];
            if (!Add(out, it->kind, x, false)) return E_NOT_OK;
        }
        return E_OK;
    }
    case UDS29_AZ_SEQ_OF_INTEGER: {
        if (t != 0x30) return E_NOT_OK;
        const uint8_t *q = v, *qe = v + l, *iv;
        size_t il;
        uint8_t it_;
        while (q < qe) {
            if (!Uds29_Der_Tlv(&q, qe, &it_, &iv, &il) || it_ != 0x02 || !UInt(iv, il, &x) || !Add(out, it->kind, x, false))
                return E_NOT_OK;
        }
        return E_OK;
    }
    default: return E_NOT_OK;
    }
}

/* Feeds every subject attribute 2.5.4.<last> (3 = CN, 11 = OU) to Decode. */
static Std_ReturnType Subject(const Uds29_CertProfileItem* it, uint8_t last, const uint8_t* der, uint16_t n, Uds29_Authz* out) {
    const uint8_t *p = der, *v, *end = der + n;
    uint8_t t;
    size_t l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return E_NOT_OK;           /* Certificate */
    p = v; end = v + l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return E_NOT_OK;           /* TBSCertificate */
    p = v; end = v + l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l)) return E_NOT_OK;
    if (t == 0xA0 && !Uds29_Der_Tlv(&p, end, &t, &v, &l)) return E_NOT_OK;           /* [0] version, then serialNumber */
    for (int i = 0; i < 3; i++) if (!Uds29_Der_Tlv(&p, end, &t, &v, &l)) return E_NOT_OK; /* sigAlg, issuer, validity */
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return E_NOT_OK;           /* subject */
    for (p = v, end = v + l; Uds29_Der_Tlv(&p, end, &t, &v, &l); ) {                 /* RDNs (SET) */
        const uint8_t *a = v, *ae = v + l, *av;
        size_t al;
        uint8_t at;
        while (Uds29_Der_Tlv(&a, ae, &at, &av, &al) && at == 0x30) {                 /* AttributeTypeAndValue */
            const uint8_t *q = av, *ov, *sv;
            size_t ol, sl;
            uint8_t ot, st;
            if (Uds29_Der_Tlv(&q, av + al, &ot, &ov, &ol) && ot == 0x06 && ol == 3 && !memcmp(ov, "\x55\x04", 2) && ov[2] == last &&
                Uds29_Der_Tlv(&q, av + al, &st, &sv, &sl) && (st == 0x0C || st == 0x13 || st == 0x16 || st == 0x14) && sl <= 0xFFFFu &&
                Uds29_Authz_Decode(it, sv, (uint16_t)sl, out) != E_OK)
                return E_NOT_OK;
        }
    }
    return E_OK;
}

Std_ReturnType Uds29_Authz_FromCert(const Uds29_CertProfile* pr, const uint8_t* der, uint16_t len, Uds29_Authz* out) {
    if (!out) return E_PARAM_POINTER;
    memset(out, 0, sizeof *out);
    if (!pr || !der) return E_PARAM_POINTER;
    for (unsigned i = 0; i < pr->count; i++) {
        const Uds29_CertProfileItem* it = &pr->items[i];
        if (it->source == UDS29_AZ_SUBJECT_OU || it->source == UDS29_AZ_SUBJECT_CN) {
            if (Subject(it, it->source == UDS29_AZ_SUBJECT_OU ? 0x0B : 0x03, der, len, out) != E_OK) return E_NOT_OK;
            continue;
        }
        uint8_t oid[32], on = 0, buf[UDS29_MAX_CERT_LEN];
        uint16_t n = 0;
        if (it->oid_der) {
            if (it->oid_der_len > sizeof oid) return E_NOT_OK;
            memcpy(oid, it->oid_der, it->oid_der_len);
            on = it->oid_der_len;
        } else if (!it->oid || !OidFromDotted(it->oid, oid, sizeof oid, &on)) return E_NOT_OK;
        if (Uds29_Crypto_GetExtension(der, len, oid, on, buf, sizeof buf, &n) != E_OK) continue; /* absent / unsupported */
        if (Uds29_Authz_Decode(it, buf, n, out) != E_OK) return E_NOT_OK;
    }
    return E_OK;
}
