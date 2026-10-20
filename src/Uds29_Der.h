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
