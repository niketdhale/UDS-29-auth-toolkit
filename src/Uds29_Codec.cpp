#include "Uds29_Codec.h"
#include <cstring>

namespace {

/* Writer and Reader expose the same field calls so each message layout is
   written once (Layout templates below) and used for both directions. */
struct Writer {
    Uds29_Bytes b;
    bool ok = true;
    void u8(uint8_t& v) { b.push_back(v); }
    void u16(uint16_t& v) { b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v)); }
    void alg(uint8_t (&a)[UDS29_ALGORITHM_INDICATOR_LEN]) { b.insert(b.end(), a, a + sizeof a); }
    void lp(Uds29_Bytes& v) {
        if (v.size() > 0xFFFF) { ok = false; return; }
        uint16_t n = uint16_t(v.size());
        u16(n);
        b.insert(b.end(), v.begin(), v.end());
    }
};

struct Reader {
    const uint8_t* d; size_t n; size_t i = 0; bool ok = true;
    Reader(const uint8_t* d_, size_t n_) : d(d_), n(n_) {}
    void u8(uint8_t& v) { if (i + 1 > n) { ok = false; return; } v = d[i++]; }
    void u16(uint16_t& v) { if (i + 2 > n) { ok = false; return; } v = uint16_t(d[i] << 8 | d[i + 1]); i += 2; }
    void alg(uint8_t (&a)[UDS29_ALGORITHM_INDICATOR_LEN]) {
        if (i + sizeof a > n) { ok = false; return; }
        std::memcpy(a, d + i, sizeof a); i += sizeof a;
    }
    void lp(Uds29_Bytes& v) {
        uint16_t len = 0; u16(len);
        if (!ok || i + len > n) { ok = false; return; }
        v.assign(d + i, d + i + len); i += len;
    }
};

/* Fields following the sub-function byte of a request. */
template <class A> void ReqLayout(A& a, Uds29_Req& r) {
    switch (r.sub) {
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL:  a.u8(r.comm); a.lp(r.cert); a.lp(r.challenge); break;
    case UDS29_SF_PROOF_OF_OWNERSHIP:         a.lp(r.pown); a.lp(r.eph); break;
    case UDS29_SF_TRANSMIT_CERTIFICATE:       a.u16(r.eval_id); a.lp(r.cert); break;
    case UDS29_SF_REQUEST_CHALLENGE:          a.u8(r.comm); a.alg(r.alg); break;
    case UDS29_SF_VERIFY_POWN_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_POWN_BIDIRECTIONAL:  a.alg(r.alg); a.lp(r.pown); a.lp(r.challenge); a.lp(r.addl); break;
    default: break; /* 0x00 and 0x08 carry no further fields */
    }
}

/* Fields following the sub-function byte of a positive response. */
template <class A> void RespLayout(A& a, Uds29_Resp& r) {
    a.u8(r.ret);
    switch (r.sub) {
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL: a.lp(r.challenge); a.lp(r.eph); break;
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL:  a.lp(r.challenge); a.lp(r.cert); a.lp(r.pown); a.lp(r.eph); break;
    case UDS29_SF_PROOF_OF_OWNERSHIP:         a.lp(r.session_key); break;
    case UDS29_SF_REQUEST_CHALLENGE:          a.alg(r.alg); a.lp(r.challenge); a.lp(r.addl); break;
    case UDS29_SF_VERIFY_POWN_UNIDIRECTIONAL: a.alg(r.alg); a.lp(r.session_key); break;
    case UDS29_SF_VERIFY_POWN_BIDIRECTIONAL:  a.alg(r.alg); a.lp(r.pown); a.lp(r.session_key); break;
    default: break;
    }
}

} // namespace

namespace Uds29Codec {

Uds29_Bytes EncodeRequest(const Uds29_Req& req) {
    Uds29_Req r = req;
    if (r.sub > UDS29_SF_AUTHENTICATION_CONFIGURATION) return {};
    Writer w;
    w.b = {UDS29_SID_REQUEST, r.sub};
    ReqLayout(w, r);
    return w.ok ? w.b : Uds29_Bytes{};
}

Uds29_Bytes EncodeResponse(const Uds29_Resp& resp) {
    Uds29_Resp r = resp;
    if (r.neg) return {UDS29_SID_NEGATIVE, UDS29_SID_REQUEST, r.nrc};
    if (r.sub > UDS29_SF_AUTHENTICATION_CONFIGURATION) return {};
    Writer w;
    w.b = {UDS29_SID_RESPONSE, r.sub};
    RespLayout(w, r);
    return w.ok ? w.b : Uds29_Bytes{};
}

bool DecodeRequest(const uint8_t* d, size_t n, Uds29_Req& r) {
    if (!d || n < 2 || d[0] != UDS29_SID_REQUEST || d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION) return false;
    r = Uds29_Req();
    r.sub = d[1];
    Reader rd(d + 2, n - 2);
    ReqLayout(rd, r);
    return rd.ok && rd.i == rd.n;
}

bool DecodeResponse(const uint8_t* d, size_t n, Uds29_Resp& r) {
    r = Uds29_Resp();
    if (!d || n < 1) return false;
    if (d[0] == UDS29_SID_NEGATIVE) {
        if (n != 3 || d[1] != UDS29_SID_REQUEST) return false;
        r.neg = true; r.nrc = d[2];
        return true;
    }
    if (n < 3 || d[0] != UDS29_SID_RESPONSE || d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION) return false;
    r.sub = d[1];
    Reader rd(d + 2, n - 2);
    RespLayout(rd, r);
    return rd.ok && rd.i == rd.n;
}

const char* NrcToString(uint8_t nrc) {
    switch (nrc) {
    case 0x12: return "subFunctionNotSupported";
    case 0x13: return "incorrectMessageLengthOrInvalidFormat";
    case 0x24: return "requestSequenceError";
    case 0x31: return "requestOutOfRange";
    case 0x34: return "authenticationRequired";
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

const char* ReturnParamToString(uint8_t ret) {
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

} // namespace Uds29Codec
