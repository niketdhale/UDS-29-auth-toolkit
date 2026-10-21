#pragma once
/* Internal bounded DER reader (not installed). Header-only so the crypto backends and the authorization
   parser share it without extra link dependencies. Lengths are limited to two length octets (<= 65535). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Reads one TLV at *p (single-byte tags only) and advances *p past it. */
static inline bool Uds29_Der_Tlv(const uint8_t** p, const uint8_t* end, uint8_t* tag, const uint8_t** v, size_t* vl) {
    if (end - *p < 2) return false;
    const uint8_t* q = *p;
    *tag = q[0];
    size_t l = q[1];
    q += 2;
    if (l & 0x80) {
        unsigned k = l & 0x7Fu;
        if (k < 1 || k > 2 || (size_t)(end - q) < k) return false;
        for (l = 0; k--; ) l = (l << 8) | *q++;
    }
    if ((size_t)(end - q) < l) return false;
    *v = q; *vl = l; *p = q + l;
    return true;
}

/* seq = the DER of the Extensions SEQUENCE (header included); oid = OID content bytes (no tag/length).
   On success the extnValue (val, vl) is content, i.e. the DER inside the OCTET STRING wrapper. */
static inline bool Uds29_Der_FindExt(const uint8_t* seq, size_t n, const uint8_t* oid, size_t oid_len,
                                     const uint8_t** val, size_t* vl) {
    const uint8_t *p = seq, *end = seq + n, *v;
    uint8_t t;
    size_t l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;
    for (p = v, end = v + l; Uds29_Der_Tlv(&p, end, &t, &v, &l); ) {
        const uint8_t *q = v, *qe = v + l, *ov, *xv;
        size_t ol, xl;
        uint8_t ot;
        if (t != 0x30 || !Uds29_Der_Tlv(&q, qe, &ot, &ov, &ol) || ot != 0x06) continue;
        if (!Uds29_Der_Tlv(&q, qe, &ot, &xv, &xl)) continue;
        if (ot == 0x01 && !Uds29_Der_Tlv(&q, qe, &ot, &xv, &xl)) continue; /* skip 'critical' */
        if (ot == 0x04 && ol == oid_len && !memcmp(ov, oid, oid_len)) { *val = xv; *vl = xl; return true; }
    }
    return false;
}

/* ── X.509 certificate walk (TBSCertificate fields used by the validation policy and the CLI) ── */
typedef struct {
    const uint8_t *serial, *sigalg, *spki, *exts; /* serial/sigalg: content of the INTEGER / of the algorithm OID;
                                                     spki: SubjectPublicKeyInfo content; exts: Extensions SEQUENCE incl. header (NULL = none) */
    size_t serial_len, sigalg_len, spki_len, exts_len;
} Uds29_DerCert;

static inline bool Uds29_Der_ParseCert(const uint8_t* der, size_t n, Uds29_DerCert* c) {
    const uint8_t *p = der, *end = der + n, *v, *s;
    uint8_t t;
    size_t l;
    memset(c, 0, sizeof *c);
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;
    p = v; end = v + l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;   /* TBSCertificate */
    p = v; end = v + l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l)) return false;
    if (t == 0xA0 && !Uds29_Der_Tlv(&p, end, &t, &v, &l)) return false;   /* [0] version */
    if (t != 0x02) return false;
    c->serial = v; c->serial_len = l;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;   /* signature AlgorithmIdentifier */
    s = v;
    if (!Uds29_Der_Tlv(&s, v + l, &t, &c->sigalg, &c->sigalg_len) || t != 0x06) return false;
    for (int i = 0; i < 3; i++)                                            /* issuer, validity, subject */
        if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;
    if (!Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return false;   /* SubjectPublicKeyInfo */
    c->spki = v; c->spki_len = l;
    while (p < end) {
        if (!Uds29_Der_Tlv(&p, end, &t, &v, &l)) return false;
        if (t == 0xA3) {                                                   /* [3] extensions */
            s = v;
            if (!Uds29_Der_Tlv(&s, v + l, &t, &c->exts, &c->exts_len) || t != 0x30) return false;
            c->exts = v; c->exts_len = (size_t)(s - v);                    /* keep the SEQUENCE header */
        }
    }
    return true;
}

/* Wire-order helpers over a parsed certificate. */
static inline bool Uds29_Der_SerialEq(const uint8_t* a, size_t al, const uint8_t* b, size_t bl) {
    while (al > 1 && *a == 0) { a++; al--; }
    while (bl > 1 && *b == 0) { b++; bl--; }
    return al == bl && !memcmp(a, b, al);
}

/* Key type as UDS29_KEY_* (0 = unknown / unsupported). */
static inline unsigned Uds29_Der_KeyType(const Uds29_DerCert* c) {
    static const uint8_t ec[] = {0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01}, p256[] = {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07},
                         p384[] = {0x2B,0x81,0x04,0x00,0x22}, ed[] = {0x2B,0x65,0x70};
    const uint8_t *p = c->spki, *end = c->spki + c->spki_len, *v, *a, *o, *q;
    uint8_t t;
    size_t l, ol, ql;
    if (!p || !Uds29_Der_Tlv(&p, end, &t, &v, &l) || t != 0x30) return 0;  /* AlgorithmIdentifier */
    a = v;
    if (!Uds29_Der_Tlv(&a, v + l, &t, &o, &ol) || t != 0x06) return 0;
    if (ol == sizeof ed && !memcmp(o, ed, ol)) return 0x04u;               /* UDS29_KEY_ED25519 */
    if (ol != sizeof ec || memcmp(o, ec, ol) || !Uds29_Der_Tlv(&a, v + l, &t, &q, &ql) || t != 0x06) return 0;
    if (ql == sizeof p256 && !memcmp(q, p256, ql)) return 0x01u;           /* UDS29_KEY_EC_P256 */
    if (ql == sizeof p384 && !memcmp(q, p384, ql)) return 0x02u;           /* UDS29_KEY_EC_P384 */
    return 0;
}

/* signatureAlgorithm as UDS29_SIG_* (0 = unknown). */
static inline unsigned Uds29_Der_SigAlg(const Uds29_DerCert* c) {
    static const uint8_t s256[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02}, s384[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03},
                         ed[] = {0x2B,0x65,0x70};
    if (c->sigalg_len == sizeof s256 && !memcmp(c->sigalg, s256, sizeof s256)) return 0x01u;
    if (c->sigalg_len == sizeof s384 && !memcmp(c->sigalg, s384, sizeof s384)) return 0x02u;
    if (c->sigalg_len == sizeof ed && !memcmp(c->sigalg, ed, sizeof ed)) return 0x04u;
    return 0;
}

/* keyUsage: bit 0 (digitalSignature) = 0x8000 ... bit 8 (decipherOnly) = 0x0080. False if absent / malformed. */
static inline bool Uds29_Der_KeyUsage(const Uds29_DerCert* c, unsigned* bits) {
    static const uint8_t oid[] = {0x55, 0x1D, 0x0F};
    const uint8_t* v;
    size_t vl;
    if (!c->exts || !Uds29_Der_FindExt(c->exts, c->exts_len, oid, sizeof oid, &v, &vl)) return false;
    const uint8_t *p = v, *bv;
    uint8_t t;
    size_t bl;
    if (!Uds29_Der_Tlv(&p, v + vl, &t, &bv, &bl) || t != 0x03 || bl < 2) return false;
    *bits = (unsigned)(bv[1] << 8) | (bl > 2 ? bv[2] : 0u);
    return true;
}

/* extKeyUsage: the content of the SEQUENCE OF KeyPurposeId (iterate with Uds29_Der_Tlv). False if absent. */
static inline bool Uds29_Der_Eku(const Uds29_DerCert* c, const uint8_t** list, size_t* n) {
    static const uint8_t oid[] = {0x55, 0x1D, 0x25};
    const uint8_t* v;
    size_t vl;
    uint8_t t;
    if (!c->exts || !Uds29_Der_FindExt(c->exts, c->exts_len, oid, sizeof oid, &v, &vl)) return false;
    const uint8_t* p = v;
    return Uds29_Der_Tlv(&p, v + vl, &t, list, n) && t == 0x30;
}
