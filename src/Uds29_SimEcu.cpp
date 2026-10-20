#include "Uds29_SimEcu.h"
#include <cstring>
#include <ctime>

namespace {
Uds29_Bytes Enc(const Uds29_Resp& r) {
    uint8_t b[UDS29_MAX_MSG_LEN];
    return Uds29_Bytes(b, b + Uds29_Codec_EncodeResponse(&r, b, sizeof b));
}
Uds29_Bytes Neg(uint8_t nrc) {
    Uds29_Resp r{}; r.neg = true; r.nrc = nrc;
    return Enc(r);
}
}

bool Uds29SimEcu::Init(const Uds29_PkiConfigType& cfg) {
    Uds29_Crypto_FreeIdentity(id_);
    id_ = Uds29_Crypto_LoadIdentity(&cfg, "ecu", cert_, sizeof cert_, &cert_len_);
    return id_ != nullptr;
}

Std_ReturnType Uds29SimEcu::Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    if (!req || !resp || !resp_len || !ctx) return E_PARAM_POINTER;
    Uds29_Bytes out = static_cast<Uds29SimEcu*>(ctx)->Handle(req, len);
    if (out.empty() || out.size() > *resp_len) return E_NOT_OK;
    std::memcpy(resp, out.data(), out.size());
    *resp_len = uint16_t(out.size());
    return E_OK;
}

Uds29_Bytes Uds29SimEcu::Handle(const uint8_t* d, size_t n) {
    Uds29_Req rq;
    if (n < 2 || d[0] != UDS29_SID_REQUEST) return Neg(UDS29_NRC_INCORRECT_LENGTH);
    if (d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION) return Neg(UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED);
    if (!Uds29_Codec_DecodeRequest(d, n, &rq)) return Neg(UDS29_NRC_INCORRECT_LENGTH); /* also: a field above the core's buffer sizes */
    if (fault_ == UDS29_SIM_FAULT_FORCE_NRC) return Neg(forced_nrc_);
    if (!id_) return Neg(UDS29_NRC_REQUEST_OUT_OF_RANGE);

    Uds29_Resp rs{};
    rs.sub = rq.sub;
    switch (rq.sub) {
    case UDS29_SF_DEAUTHENTICATE:
        cert_ok_ = false;
        rs.ret = UDS29_RET_DEAUTHENTICATION_SUCCESSFUL;
        break;
    case UDS29_SF_AUTHENTICATION_CONFIGURATION:
        rs.ret = UDS29_RET_AUTH_CONFIG_APCE;
        break;
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL: {
        cert_ok_ = false;
        if (fault_ == UDS29_SIM_FAULT_WRONG_CERT_FORMAT && rq.sub == UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL)
            return Neg(UDS29_NRC_CVF_INVALID_FORMAT);
        int64_t at = fault_ == UDS29_SIM_FAULT_EXPIRED_CERT ? int64_t(time(nullptr)) + 11LL * 365 * 86400 : 0;
        switch (Uds29_Crypto_VerifyPeer(id_, rq.cert, rq.cert_len, at)) {
        case UDS29_PKI_OK: break;
        case UDS29_PKI_PARSE: return Neg(UDS29_NRC_CVF_INVALID_FORMAT);
        case UDS29_PKI_EXPIRED: return Neg(UDS29_NRC_CVF_INVALID_TIME_PERIOD);
        default: return Neg(UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST);
        }
        client_cert_.assign(rq.cert, rq.cert + rq.cert_len);
        challenge_server_.assign(32, 0);
        if (Uds29_Crypto_Random(challenge_server_.data(), 32) != E_OK) return Neg(UDS29_NRC_CHALLENGE_CALCULATION_FAILED);
        cert_ok_ = true;
        rs.ret = UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY;
        std::memcpy(rs.challenge, challenge_server_.data(), 32);
        rs.challenge_len = 32;
        if (rq.sub == UDS29_SF_VERIFY_CERT_BIDIRECTIONAL) {
            uint8_t signed_data[UDS29_MAX_CHALLENGE_LEN + 1];
            uint16_t sn = rq.challenge_len;
            std::memcpy(signed_data, rq.challenge, sn);
            if (fault_ == UDS29_SIM_FAULT_CHALLENGE_MISMATCH) signed_data[sn++] = 0xFF;
            if (fault_ == UDS29_SIM_FAULT_WRONG_CERT_FORMAT) { const uint8_t g[] = {0xDE, 0xAD, 0xBE, 0xEF}; std::memcpy(rs.cert, g, 4); rs.cert_len = 4; }
            else { std::memcpy(rs.cert, cert_, cert_len_); rs.cert_len = cert_len_; }
            if (Uds29_Crypto_Sign(id_, signed_data, sn, rs.pown, sizeof rs.pown, &rs.pown_len) != E_OK)
                return Neg(UDS29_NRC_CHALLENGE_CALCULATION_FAILED);
            if (fault_ == UDS29_SIM_FAULT_BAD_SIGNATURE && rs.pown_len) rs.pown[rs.pown_len - 1] ^= 0x01;
        }
        break;
    }
    case UDS29_SF_PROOF_OF_OWNERSHIP: {
        if (!cert_ok_) return Neg(UDS29_NRC_REQUEST_SEQUENCE_ERROR);
        Uds29_Bytes sig(rq.pown, rq.pown + rq.pown_len), expected = challenge_server_;
        if (fault_ == UDS29_SIM_FAULT_BAD_SIGNATURE && !sig.empty()) sig.back() ^= 0x01;
        if (fault_ == UDS29_SIM_FAULT_CHALLENGE_MISMATCH) expected.push_back(0xFF);
        cert_ok_ = false;
        if (sig.empty() || sig.size() > 0xFFFF || expected.size() > 0xFFFF ||
            Uds29_Crypto_Verify(client_cert_.data(), uint16_t(client_cert_.size()), expected.data(), uint16_t(expected.size()),
                                sig.data(), uint16_t(sig.size())) != E_OK)
            return Neg(UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED);
        rs.ret = UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE;
        break;
    }
    default:
        return Neg(UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED);
    }
    return Enc(rs);
}

#include "Uds29_SimEcu_C.h"
extern "C" {
void* Uds29_SimEcu_New(const Uds29_PkiConfigType* pki) {
    Uds29SimEcu* e = new Uds29SimEcu();
    if (!e->Init(*pki)) { delete e; return nullptr; }
    return e;
}
void Uds29_SimEcu_Free(void* ecu) { delete static_cast<Uds29SimEcu*>(ecu); }
Std_ReturnType Uds29_SimEcu_Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    return Uds29SimEcu::Transport(req, len, resp, resp_len, ctx);
}
}
