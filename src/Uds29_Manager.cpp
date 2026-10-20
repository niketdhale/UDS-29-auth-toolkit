#include "Uds29_Internal.h"
#include "Uds29_Manager_Wrapper.h"
#include <algorithm>
#include <cstring>

typedef std::lock_guard<std::recursive_mutex> Lock;

Std_ReturnType Uds29_Manager::Init(const Uds29_ConfigType& cfg) {
    Lock l(mtx_);
    cfg_ = cfg;
    init_ = true;
    state_ = UDS29_STATE_IDLE;
    log_.clear();
    return E_OK;
}

Std_ReturnType Uds29_Manager::DeInit() {
    Lock l(mtx_);
    init_ = pki_ok_ = false;
    tp_ = nullptr; tp_ctx_ = nullptr; cb_ = nullptr;
    state_ = UDS29_STATE_IDLE;
    log_.clear();
    return E_OK;
}

Std_ReturnType Uds29_Manager::SetTransport(Uds29_TransportFn fn, void* ctx) {
    Lock l(mtx_);
    tp_ = fn; tp_ctx_ = ctx;
    return E_OK;
}

Std_ReturnType Uds29_Manager::SetPki(const Uds29_PkiConfigType& pki) {
    Lock l(mtx_);
    pki_ok_ = pki_.Load(pki, "tester");
    return pki_ok_ ? E_OK : E_NOT_OK;
}

void Uds29_Manager::SetEventCallback(Uds29_EventCallback cb) { Lock l(mtx_); cb_ = cb; }
Uds29_StateType Uds29_Manager::GetState() { Lock l(mtx_); return state_; }

void Uds29_Manager::Emit(Uds29_EventKindType k, uint8_t sub, uint8_t nrc, const char* why) {
    if (!cb_) return;
    Uds29_EventType e{k, state_, sub, nrc, why};
    cb_(&e);
}

void Uds29_Manager::SetState(Uds29_StateType s) {
    if (s == state_) return;
    state_ = s;
    Emit(UDS29_EVT_STATE_CHANGE, 0, 0, "");
}

Std_ReturnType Uds29_Manager::Fail(uint8_t sub, const char* why, uint8_t nrc) {
    SetState(UDS29_STATE_FAILED);
    Emit(UDS29_EVT_FAILURE, sub, nrc, why);
    return E_NOT_OK;
}

void Uds29_Manager::Log(Uds29_DirectionType d, const uint8_t* p, size_t n) {
    log_.push_back({d, Uds29_Bytes(p, p + n)});
}

Std_ReturnType Uds29_Manager::Transfer(const uint8_t* tx, uint16_t n, uint8_t* rx, uint16_t* rx_n) {
    Log(UDS29_DIR_TX, tx, n);
    Std_ReturnType r = tp_(tx, n, rx, rx_n, tp_ctx_);
    if (r == E_OK) Log(UDS29_DIR_RX, rx, *rx_n);
    return r;
}

/* One request/response round trip; any failure moves the session to FAILED. */
Std_ReturnType Uds29_Manager::Exchange(const Uds29_Req& rq, Uds29_Resp& rs) {
    Uds29_Bytes tx = Uds29Codec::EncodeRequest(rq);
    if (tx.empty() || tx.size() > 0xFFFF) return Fail(rq.sub, "request encoding failed");
    uint8_t buf[4096];
    uint16_t n = sizeof buf;
    if (Transfer(tx.data(), uint16_t(tx.size()), buf, &n) != E_OK) return Fail(rq.sub, "transport error");
    if (!Uds29Codec::DecodeResponse(buf, n, rs)) return Fail(rq.sub, "malformed response");
    if (rs.neg) return Fail(rq.sub, Uds29Codec::NrcToString(rs.nrc), rs.nrc);
    if (rs.sub != rq.sub) return Fail(rq.sub, "response sub-function mismatch");
    return E_OK;
}

Std_ReturnType Uds29_Manager::Authenticate(bool bidi) {
    Lock l(mtx_);
    if (!init_ || !tp_ || !pki_ok_) return E_MODE_INVALID;
    SetState(UDS29_STATE_IDLE);

    Uds29_Req rq;
    rq.sub = bidi ? UDS29_SF_VERIFY_CERT_BIDIRECTIONAL : UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL;
    rq.comm = cfg_.comm_config;
    rq.cert = pki_.CertDer();
    rq.challenge = Uds29Pki::Random(cfg_.challenge_len);
    Uds29_Resp rs;
    SetState(UDS29_STATE_CERT_SENT);
    if (Exchange(rq, rs) != E_OK) return E_NOT_OK;
    if (rs.ret != UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY || rs.challenge.empty())
        return Fail(rq.sub, "unexpected authenticationReturnParameter");
    SetState(UDS29_STATE_CHALLENGE_RECEIVED);

    if (bidi) {
        Uds29_PkiResult v = pki_.VerifyPeer(rs.cert);
        if (v != UDS29_PKI_OK)
            return Fail(rq.sub, v == UDS29_PKI_PARSE ? "ECU certificate unparsable"
                              : v == UDS29_PKI_EXPIRED ? "ECU certificate expired"
                                                       : "ECU certificate chain invalid");
        if (!Uds29Pki::Verify(rs.cert, rq.challenge, rs.pown))
            return Fail(rq.sub, "ECU proof of ownership invalid");
    }

    Uds29_Req pr;
    pr.sub = UDS29_SF_PROOF_OF_OWNERSHIP;
    if (!pki_.Sign(rs.challenge, pr.pown)) return Fail(pr.sub, "signing failed");
    SetState(UDS29_STATE_POWN_SENT);
    if (Exchange(pr, rs) != E_OK) return E_NOT_OK;
    if (rs.ret != UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE)
        return Fail(pr.sub, "unexpected authenticationReturnParameter");
    SetState(UDS29_STATE_AUTHENTICATED);
    return E_OK;
}

Std_ReturnType Uds29_Manager::DeAuthenticate() {
    Lock l(mtx_);
    if (!init_ || !tp_) return E_MODE_INVALID;
    Uds29_Req rq;
    rq.sub = UDS29_SF_DEAUTHENTICATE;
    Uds29_Resp rs;
    if (Exchange(rq, rs) != E_OK) return E_NOT_OK;
    if (rs.ret != UDS29_RET_DEAUTHENTICATION_SUCCESSFUL) return Fail(rq.sub, "unexpected authenticationReturnParameter");
    SetState(UDS29_STATE_IDLE);
    return E_OK;
}

Std_ReturnType Uds29_Manager::SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len) {
    Lock l(mtx_);
    if (!init_ || !tp_) return E_MODE_INVALID;
    return Transfer(req, len, resp, resp_len);
}

uint32_t Uds29_Manager::GetLogCount() { Lock l(mtx_); return uint32_t(log_.size()); }

Std_ReturnType Uds29_Manager::GetLogEntry(uint32_t i, Uds29_DirectionType* dir, uint8_t* buf, uint16_t cap, uint16_t* len) {
    Lock l(mtx_);
    if (i >= log_.size()) return E_NOT_OK;
    const LogEntry& e = log_[i];
    *dir = e.dir;
    *len = uint16_t(std::min<size_t>(e.data.size(), cap));
    std::memcpy(buf, e.data.data(), *len);
    return E_OK;
}

void Uds29_Manager::ClearLog() { Lock l(mtx_); log_.clear(); }

/* ── C bridge ─────────────────────────────────────────────────────────────── */
extern "C" {
Std_ReturnType Uds29_Core_Init(const Uds29_ConfigType* c) { return Uds29_Manager::Instance().Init(*c); }
Std_ReturnType Uds29_Core_DeInit(void) { return Uds29_Manager::Instance().DeInit(); }
Std_ReturnType Uds29_Core_SetTransport(Uds29_TransportFn fn, void* ctx) { return Uds29_Manager::Instance().SetTransport(fn, ctx); }
Std_ReturnType Uds29_Core_SetPki(const Uds29_PkiConfigType* p) { return Uds29_Manager::Instance().SetPki(*p); }
void Uds29_Core_SetEventCallback(Uds29_EventCallback cb) { Uds29_Manager::Instance().SetEventCallback(cb); }
Std_ReturnType Uds29_Core_Authenticate(bool bidi) { return Uds29_Manager::Instance().Authenticate(bidi); }
Std_ReturnType Uds29_Core_DeAuthenticate(void) { return Uds29_Manager::Instance().DeAuthenticate(); }
Uds29_StateType Uds29_Core_GetState(void) { return Uds29_Manager::Instance().GetState(); }
Std_ReturnType Uds29_Core_SendRaw(const uint8_t* r, uint16_t n, uint8_t* o, uint16_t* on) { return Uds29_Manager::Instance().SendRaw(r, n, o, on); }
uint32_t Uds29_Core_GetLogCount(void) { return Uds29_Manager::Instance().GetLogCount(); }
Std_ReturnType Uds29_Core_GetLogEntry(uint32_t i, Uds29_DirectionType* d, uint8_t* b, uint16_t c, uint16_t* l) { return Uds29_Manager::Instance().GetLogEntry(i, d, b, c, l); }
void Uds29_Core_ClearLog(void) { Uds29_Manager::Instance().ClearLog(); }
}
