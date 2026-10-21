#include "Uds29_Codec.h"
#include <string.h>

/* One cursor for both directions so each message layout is written once (ReqLayout/RespLayout).
   Writing: b = output, n = capacity. Reading: b = input, n = length. Every access is bounds-checked
   against n, and a variable field against its buffer size. */
typedef struct { uint8_t* b; size_t n, i; bool wr, ok; } Cur;

static void U8(Cur* c, uint8_t* v) {
    if (!c->ok || c->i + 1 > c->n) { c->ok = false; return; }
    if (c->wr) c->b[c->i++] = *v; else *v = c->b[c->i++];
}
static void U16(Cur* c, uint16_t* v) {
    if (!c->ok || c->i + 2 > c->n) { c->ok = false; return; }
    if (c->wr) { c->b[c->i++] = (uint8_t)(*v >> 8); c->b[c->i++] = (uint8_t)*v; }
    else { *v = (uint16_t)(c->b[c->i] << 8 | c->b[c->i + 1]); c->i += 2; }
}
static void Alg(Cur* c, uint8_t* a) {
    if (!c->ok || c->i + UDS29_ALGORITHM_INDICATOR_LEN > c->n) { c->ok = false; return; }
    if (c->wr) memcpy(c->b + c->i, a, UDS29_ALGORITHM_INDICATOR_LEN); else memcpy(a, c->b + c->i, UDS29_ALGORITHM_INDICATOR_LEN);
    c->i += UDS29_ALGORITHM_INDICATOR_LEN;
}
/* Length-prefixed field: *len bytes in data[cap]. */
static void Lp(Cur* c, uint16_t* len, uint8_t* data, size_t cap) {
    U16(c, len);
    if (!c->ok) return;
    if (*len > cap || c->i + *len > c->n) { c->ok = false; return; }
    if (c->wr) memcpy(c->b + c->i, data, *len); else memcpy(data, c->b + c->i, *len);
    c->i += *len;
}
#define LP(c, r, f, cap) Lp(c, &(r)->f##_len, (r)->f, cap)

/* Fields following the sub-function byte of a request. */
static void ReqLayout(Cur* c, Uds29_Req* r) {
    switch (r->sub) {
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL:  U8(c, &r->comm); LP(c, r, cert, sizeof r->cert); LP(c, r, challenge, sizeof r->challenge); break;
    case UDS29_SF_PROOF_OF_OWNERSHIP:         LP(c, r, pown, sizeof r->pown); LP(c, r, eph, sizeof r->eph); break;
    case UDS29_SF_TRANSMIT_CERTIFICATE:       U16(c, &r->eval_id); LP(c, r, cert, sizeof r->cert); break;
    case UDS29_SF_REQUEST_CHALLENGE:          U8(c, &r->comm); Alg(c, r->alg); break;
    case UDS29_SF_VERIFY_POWN_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_POWN_BIDIRECTIONAL:  Alg(c, r->alg); LP(c, r, pown, sizeof r->pown); LP(c, r, challenge, sizeof r->challenge); LP(c, r, addl, sizeof r->addl); break;
    default: break; /* 0x00 and 0x08 carry no further fields */
    }
}

/* Fields following the sub-function byte of a positive response. */
static void RespLayout(Cur* c, Uds29_Resp* r) {
    U8(c, &r->ret);
    switch (r->sub) {
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL: LP(c, r, challenge, sizeof r->challenge); LP(c, r, eph, sizeof r->eph); break;
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL:  LP(c, r, challenge, sizeof r->challenge); LP(c, r, cert, sizeof r->cert); LP(c, r, pown, sizeof r->pown); LP(c, r, eph, sizeof r->eph); break;
    case UDS29_SF_PROOF_OF_OWNERSHIP:         LP(c, r, session_key, sizeof r->session_key); break;
    case UDS29_SF_REQUEST_CHALLENGE:          Alg(c, r->alg); LP(c, r, challenge, sizeof r->challenge); LP(c, r, addl, sizeof r->addl); break;
    case UDS29_SF_VERIFY_POWN_UNIDIRECTIONAL: Alg(c, r->alg); LP(c, r, session_key, sizeof r->session_key); break;
    case UDS29_SF_VERIFY_POWN_BIDIRECTIONAL:  Alg(c, r->alg); LP(c, r, pown, sizeof r->pown); LP(c, r, session_key, sizeof r->session_key); break;
    default: break;
    }
}

uint16_t Uds29_Codec_EncodeRequest(const Uds29_Req* req, uint8_t* out, uint16_t cap) {
    if (!req || !out || req->sub > UDS29_SF_AUTHENTICATION_CONFIGURATION || cap < 2) return 0;
    Cur c = {out, cap, 2, true, true};
    out[0] = UDS29_SID_REQUEST; out[1] = req->sub;
    ReqLayout(&c, (Uds29_Req*)req); /* write mode never modifies *req */
    return c.ok ? (uint16_t)c.i : 0;
}

uint16_t Uds29_Codec_EncodeResponse(const Uds29_Resp* resp, uint8_t* out, uint16_t cap) {
    if (!resp || !out) return 0;
    if (resp->neg) {
        if (cap < 3) return 0;
        out[0] = UDS29_SID_NEGATIVE; out[1] = UDS29_SID_REQUEST; out[2] = resp->nrc;
        return 3;
    }
    if (resp->sub > UDS29_SF_AUTHENTICATION_CONFIGURATION || cap < 2) return 0;
    Cur c = {out, cap, 2, true, true};
    out[0] = UDS29_SID_RESPONSE; out[1] = resp->sub;
    RespLayout(&c, (Uds29_Resp*)resp);
    return c.ok ? (uint16_t)c.i : 0;
}

bool Uds29_Codec_DecodeRequest(const uint8_t* d, size_t n, Uds29_Req* r) {
    if (!r) return false;
    memset(r, 0, sizeof *r);
    if (!d || n < 2 || d[0] != UDS29_SID_REQUEST || d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION) return false;
    r->sub = d[1];
    Cur c = {(uint8_t*)d, n, 2, false, true}; /* read mode never writes through b */
    ReqLayout(&c, r);
    if (!(c.ok && c.i == c.n)) { memset(r, 0, sizeof *r); return false; }
    return true;
}

bool Uds29_Codec_DecodeResponse(const uint8_t* d, size_t n, Uds29_Resp* r) {
    if (!r) return false;
    memset(r, 0, sizeof *r);
    if (!d || n < 1) return false;
    if (d[0] == UDS29_SID_NEGATIVE) {
        if (n != 3 || d[1] != UDS29_SID_REQUEST) return false;
        r->neg = true; r->nrc = d[2];
        return true;
    }
    if (n < 3 || d[0] != UDS29_SID_RESPONSE || d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION) return false;
    r->sub = d[1];
    Cur c = {(uint8_t*)d, n, 2, false, true};
    RespLayout(&c, r);
    if (!(c.ok && c.i == c.n)) { memset(r, 0, sizeof *r); return false; }
    return true;
}

const char* Uds29_Codec_NrcToString(uint8_t nrc) {
    switch (nrc) {
    case 0x12: return "subFunctionNotSupported";
    case 0x13: return "incorrectMessageLengthOrInvalidFormat";
    case 0x24: return "requestSequenceError";
    case 0x31: return "requestOutOfRange";
    case 0x34: return "authenticationRequired";
    case 0x36: return "exceededNumberOfAttempts";
    case 0x37: return "requiredTimeDelayNotExpired";
    case 0x50: return "certificateVerificationFailed_InvalidTimePeriod";
    case 0x51: return "certificateVerificationFailed_InvalidSignature";
    case 0x52: return "certificateVerificationFailed_InvalidChainOfTrust";
    case 0x53: return "certificateVerificationFailed_InvalidType";
    case 0x54: return "certificateVerificationFailed_InvalidFormat";
    case 0x55: return "certificateVerificationFailed_InvalidContent";
    case 0x56: return "certificateVerificationFailed_InvalidScope";
    case 0x57: return "certificateVerificationFailed_InvalidCertificate";
    case 0x58: return "ownershipVerificationFailed";
    case 0x59: return "challengeCalculationFailed";
    case 0x5A: return "settingAccessRightsFailed";
    case 0x5B: return "sessionKeyCreationDerivationFailed";
    case 0x5C: return "configurationDataUsageFailed";
    case 0x5D: return "deAuthenticationFailed";
    default:   return "unknownNRC";
    }
}

const char* Uds29_Codec_ReturnParamToString(uint8_t ret) {
    switch (ret) {
    case 0x00: return "RequestAccepted";
    case 0x01: return "GeneralReject";
    case 0x02: return "AuthenticationConfiguration APCE";
    case 0x03: return "AuthenticationConfiguration ACR with asymmetric cryptography";
    case 0x04: return "AuthenticationConfiguration ACR with symmetric cryptography";
    case 0x10: return "DeAuthentication successful";
    case 0x11: return "CertificateVerified, OwnershipVerificationNecessary";
    case 0x12: return "OwnershipVerified, AuthenticationComplete";
    case 0x13: return "CertificateVerified";
    default:   return (ret >= 0x05 && ret <= 0x0F) ? "Reserved" : "Unknown";
    }
}


