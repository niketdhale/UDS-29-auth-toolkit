#include "Uds29_SimEcu.h"
#include <cstring>

namespace {
Uds29_Bytes Neg(uint8_t nrc) {
    Uds29_Resp r; r.neg = true; r.nrc = nrc;
    return Uds29Codec::EncodeResponse(r);
}
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
    if (!Uds29Codec::DecodeRequest(d, n, rq)) return Neg(UDS29_NRC_INCORRECT_LENGTH);
    if (fault_ == UDS29_SIM_FAULT_FORCE_NRC) return Neg(forced_nrc_);

    Uds29_Resp rs;
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
        time_t at = fault_ == UDS29_SIM_FAULT_EXPIRED_CERT ? time(nullptr) + 11LL * 365 * 86400 : 0;
        switch (pki_.VerifyPeer(rq.cert, at)) {
        case UDS29_PKI_OK: break;
        case UDS29_PKI_PARSE: return Neg(UDS29_NRC_CVF_INVALID_FORMAT);
        case UDS29_PKI_EXPIRED: return Neg(UDS29_NRC_CVF_INVALID_TIME_PERIOD);
        default: return Neg(UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST);
        }
        client_cert_ = rq.cert;
        challenge_server_ = Uds29Pki::Random(32);
        cert_ok_ = true;
        rs.ret = UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY;
        rs.challenge = challenge_server_;
        if (rq.sub == UDS29_SF_VERIFY_CERT_BIDIRECTIONAL) {
            Uds29_Bytes signed_data = rq.challenge;
            if (fault_ == UDS29_SIM_FAULT_CHALLENGE_MISMATCH) signed_data.push_back(0xFF);
            rs.cert = fault_ == UDS29_SIM_FAULT_WRONG_CERT_FORMAT ? Uds29_Bytes{0xDE, 0xAD, 0xBE, 0xEF} : pki_.CertDer();
            if (!pki_.Sign(signed_data, rs.pown)) return Neg(UDS29_NRC_CHALLENGE_CALCULATION_FAILED);
            if (fault_ == UDS29_SIM_FAULT_BAD_SIGNATURE && !rs.pown.empty()) rs.pown.back() ^= 0x01;
        }
        break;
    }
    case UDS29_SF_PROOF_OF_OWNERSHIP: {
        if (!cert_ok_) return Neg(UDS29_NRC_REQUEST_SEQUENCE_ERROR);
        Uds29_Bytes sig = rq.pown, expected = challenge_server_;
        if (fault_ == UDS29_SIM_FAULT_BAD_SIGNATURE && !sig.empty()) sig.back() ^= 0x01;
        if (fault_ == UDS29_SIM_FAULT_CHALLENGE_MISMATCH) expected.push_back(0xFF);
        cert_ok_ = false;
        if (!Uds29Pki::Verify(client_cert_, expected, sig)) return Neg(UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED);
        rs.ret = UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE;
        break;
    }
    default:
        return Neg(UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED);
    }
    return Uds29Codec::EncodeResponse(rs);
}
