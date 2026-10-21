/* Client-side session manager (state machine for SID 0x29). All state is static; every entry point takes
   the recursive OS lock because event callbacks run with it held and may call back into the API. */
#include "Uds29_Manager_Wrapper.h"
#include "Uds29_Cfg.h"
#include "Uds29_Codec.h"
#include "Uds29_Crypto.h"
#include "Uds29_Os.h"
#include "Uds29_Policy.h"
#include <string.h>

typedef enum { OP_AUTH_UNI, OP_AUTH_BI, OP_DEAUTH } Op;

typedef struct { Uds29_DirectionType dir; uint16_t len; uint8_t data[UDS29_MAX_MSG_LEN]; } LogEntry;

static struct {
    bool                init, pki_ok;
    Uds29_ConfigType    cfg;
    Uds29_Verifier      vf;                 /* policy, time source, revoked serials for the ECU certificate */
    Uds29_TransportFn   tp;
    void*               tp_ctx;
    void*               ident;
    uint8_t             cert[UDS29_MAX_CERT_LEN];
    uint16_t            cert_len;
    Uds29_StateType     state;
    Uds29_EventCallback cb;
    LogEntry            log[UDS29_LOG_DEPTH]; /* ring: oldest at log_head */
    uint32_t            log_head, log_count;
    /* session engine */
    Uds29_TxCallback    txcb;
    void*               txctx;
    uint32_t          (*clock)(void);   /* test hook, NULL = Uds29_Os_GetTimeMs */
    bool                busy, tx_ready, waiting;
    Op                  op;
    uint8_t             step, cur_sub;
    uint8_t             tx[UDS29_MAX_MSG_LEN];
    uint16_t            tx_len;
    uint32_t            t0;
    uint8_t             challenge[UDS29_MAX_CHALLENGE_LEN];
    uint8_t             challenge_len;
} g;

static void Emit(Uds29_EventKindType k, uint8_t sub, uint8_t nrc, const char* why) {
    if (!g.cb) return;
    Uds29_EventType e = {k, g.state, sub, nrc, why};
    g.cb(&e);
}

static void SetState(Uds29_StateType s) {
    if (s == g.state) return;
    g.state = s;
    Emit(UDS29_EVT_STATE_CHANGE, 0, 0, "");
}

static void Log(Uds29_DirectionType d, const uint8_t* p, size_t n) {
    uint32_t slot;
    if (g.log_count < UDS29_LOG_DEPTH) slot = (g.log_head + g.log_count++) % UDS29_LOG_DEPTH;
    else { slot = g.log_head; g.log_head = (g.log_head + 1) % UDS29_LOG_DEPTH; }
    if (n > UDS29_MAX_MSG_LEN) n = UDS29_MAX_MSG_LEN;
    g.log[slot].dir = d;
    g.log[slot].len = (uint16_t)n;
    memcpy(g.log[slot].data, p, n);
}

static void Reset(void) {
    Uds29_Crypto_FreeIdentity(g.ident);
    g.ident = NULL; g.cert_len = 0;
    g.init = g.pki_ok = false;
    memset(&g.vf, 0, sizeof g.vf);
    g.tp = NULL; g.tp_ctx = NULL; g.cb = NULL; g.txcb = NULL; g.txctx = NULL;
    g.busy = g.tx_ready = g.waiting = false;
    g.state = UDS29_STATE_IDLE;
    g.log_head = g.log_count = 0;
}

static Std_ReturnType Transfer(const uint8_t* tx, uint16_t n, uint8_t* rx, uint16_t* rx_n) {
    uint16_t cap = *rx_n;
    Log(UDS29_DIR_TX, tx, n);
    Std_ReturnType r = g.tp(tx, n, rx, rx_n, g.tp_ctx);
    if (r != E_OK) return r;
    if (*rx_n > cap) return E_NOT_OK; /* misbehaving transport: never trust a length beyond our buffer */
    Log(UDS29_DIR_RX, rx, *rx_n);
    return E_OK;
}

/* ── Session engine ────────────────────────────────────────────────────────────────
   One state machine serves both APIs. A step queues a request in g.tx (tx_ready); the blocking API sends it
   through the transport callback and feeds the reply to OnResponse at once, the non-blocking API sends it
   from MainFunction and waits for RxIndication (or the P2 timeout). */
static uint32_t Now(void) { return g.clock ? g.clock() : Uds29_Os_GetTimeMs(); }

static Std_ReturnType Fail(uint8_t sub, const char* why, uint8_t nrc) {
    g.busy = g.tx_ready = g.waiting = false;
    SetState(UDS29_STATE_FAILED);
    Emit(UDS29_EVT_FAILURE, sub, nrc, why);
    return E_NOT_OK;
}

static Std_ReturnType Queue(const Uds29_Req* rq) {
    uint16_t n = Uds29_Codec_EncodeRequest(rq, g.tx, sizeof g.tx);
    if (n == 0) return Fail(rq->sub, "request encoding failed", 0);
    g.tx_len = n; g.cur_sub = rq->sub; g.tx_ready = true;
    return E_OK;
}

static Std_ReturnType Begin(Op op) {
    if (!g.init || (op != OP_DEAUTH && !g.pki_ok)) return E_MODE_INVALID;
    if (g.busy) return E_NOT_OK;
    Uds29_Req rq;
    memset(&rq, 0, sizeof rq);
    g.op = op; g.step = 0; g.busy = true;
    if (op == OP_DEAUTH) { rq.sub = UDS29_SF_DEAUTHENTICATE; return Queue(&rq); }
    SetState(UDS29_STATE_IDLE);
    rq.sub = op == OP_AUTH_BI ? UDS29_SF_VERIFY_CERT_BIDIRECTIONAL : UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL;
    rq.comm = g.cfg.comm_config;
    memcpy(rq.cert, g.cert, g.cert_len);
    rq.cert_len = g.cert_len;
    rq.challenge_len = g.cfg.challenge_len;
    if (Uds29_Crypto_Random(rq.challenge, rq.challenge_len) != E_OK) return Fail(rq.sub, "random generation failed", 0);
    memcpy(g.challenge, rq.challenge, rq.challenge_len);
    g.challenge_len = rq.challenge_len;
    SetState(UDS29_STATE_CERT_SENT);
    return Queue(&rq);
}

/* Consumes one response for the request in flight (already logged). Any failure moves the session to FAILED. */
static Std_ReturnType OnResponse(const uint8_t* rx, uint16_t rn) {
    Uds29_Resp rs;
    uint8_t sub = g.cur_sub;
    if (!Uds29_Codec_DecodeResponse(rx, rn, &rs)) return Fail(sub, "malformed response", 0);
    if (rs.neg) return Fail(sub, Uds29_Codec_NrcToString(rs.nrc), rs.nrc);
    if (rs.sub != sub) return Fail(sub, "response sub-function mismatch", 0);

    if (g.op == OP_DEAUTH) {
        if (rs.ret != UDS29_RET_DEAUTHENTICATION_SUCCESSFUL) return Fail(sub, "unexpected authenticationReturnParameter", 0);
        g.busy = false;
        SetState(UDS29_STATE_IDLE);
        return E_OK;
    }
    if (g.step == 0) {
        if (rs.ret != UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY || rs.challenge_len == 0)
            return Fail(sub, "unexpected authenticationReturnParameter", 0);
        SetState(UDS29_STATE_CHALLENGE_RECEIVED);
        Uds29_PownIn in;
        memset(&in, 0, sizeof in);
        in.server_ch = rs.challenge; in.server_len = rs.challenge_len;
        in.client_ch = g.challenge;  in.client_len = g.challenge_len;
        in.own_cert = g.cert; in.own_len = g.cert_len;
        in.comm = g.cfg.comm_config; in.bidi = g.op == OP_AUTH_BI;
        if (g.op == OP_AUTH_BI) {
            bool skipped;
            Uds29_PkiResult v = Uds29_Verifier_Check(&g.vf, g.ident, rs.cert, rs.cert_len, 0, &skipped);
            if (skipped) Emit(UDS29_EVT_WARNING, sub, 0, "validity not checked");
            if (v != UDS29_PKI_OK)
                return Fail(sub, v == UDS29_PKI_PARSE ? "ECU certificate unparsable"
                               : v == UDS29_PKI_EXPIRED ? "ECU certificate expired"
                               : v == UDS29_PKI_REVOKED ? "ECU certificate revoked"
                               : v == UDS29_PKI_SIGNATURE ? "ECU certificate signature invalid"
                               : v == UDS29_PKI_POLICY_ALG ? "ECU certificate algorithm not allowed by the certificate policy"
                               : v == UDS29_PKI_POLICY || v == UDS29_PKI_POLICY_USAGE ? "ECU certificate violates the certificate policy"
                               : v == UDS29_PKI_TIME_UNTRUSTED ? "no trusted time to check the ECU certificate"
                                                        : "ECU certificate chain invalid", 0);
            Uds29_PownIn ecu = in;                                 /* the ECU is the signer here: OWN = its certificate */
            ecu.own_cert = rs.cert; ecu.own_len = rs.cert_len;
            ecu.peer_cert = g.cert; ecu.peer_len = g.cert_len;
            ecu.raw = g.challenge; ecu.raw_len = g.challenge_len;  /* the ECU signs the challenge we issued */
            uint8_t data[UDS29_POWN_DATA_MAX];
            uint16_t dn;
            if (!Uds29_Pown_Build(&g.cfg.pown, &ecu, data, sizeof data, &dn) ||
                Uds29_Crypto_Verify(rs.cert, rs.cert_len, data, dn, rs.pown, rs.pown_len) != E_OK)
                return Fail(sub, "ECU proof of ownership invalid", 0);
        }
        Uds29_Req pr;
        memset(&pr, 0, sizeof pr);
        pr.sub = UDS29_SF_PROOF_OF_OWNERSHIP;
        if (g.op == OP_AUTH_BI) { in.peer_cert = rs.cert; in.peer_len = rs.cert_len; } /* uni: the ECU certificate is not known */
        in.raw = rs.challenge; in.raw_len = rs.challenge_len;     /* we sign the challenge the ECU issued */
        uint8_t data[UDS29_POWN_DATA_MAX];
        uint16_t dn;
        if (!Uds29_Pown_Build(&g.cfg.pown, &in, data, sizeof data, &dn) ||
            Uds29_Crypto_Sign(g.ident, data, dn, pr.pown, sizeof pr.pown, &pr.pown_len) != E_OK)
            return Fail(pr.sub, "signing failed", 0);
        SetState(UDS29_STATE_POWN_SENT);
        g.step = 1;
        return Queue(&pr);
    }
    if (rs.ret != UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE) return Fail(sub, "unexpected authenticationReturnParameter", 0);
    g.busy = false;
    SetState(UDS29_STATE_AUTHENTICATED);
    return E_OK;
}

/* Blocking API: drive the engine through the transport callback until it finishes. */
static Std_ReturnType Run(Op op) {
    if (!g.init || !g.tp) return E_MODE_INVALID;
    Std_ReturnType r = Begin(op);
    uint8_t rx[UDS29_MAX_MSG_LEN];
    while (r == E_OK && g.busy && g.tx_ready) {
        uint16_t rn = sizeof rx;
        g.tx_ready = false;
        if (Transfer(g.tx, g.tx_len, rx, &rn) != E_OK) r = Fail(g.cur_sub, "transport error", 0);
        else r = OnResponse(rx, rn);
    }
    return r;
}

/* ── C API (serialised by the OS lock) ────────────────────────────────────── */
Std_ReturnType Uds29_Core_Init(const Uds29_ConfigType* c) {
    if (c->challenge_len > UDS29_MAX_CHALLENGE_LEN) return E_NOT_OK;
    Uds29_Os_Lock();
    g.cfg = *c;
    g.vf.policy = c->policy;
    g.init = true;
    g.busy = g.tx_ready = g.waiting = false;
    g.state = UDS29_STATE_IDLE;
    g.log_head = g.log_count = 0;
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29_Core_DeInit(void) {
    Uds29_Os_Lock();
    Reset();
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29_Core_SetTransport(Uds29_TransportFn fn, void* ctx) {
    Uds29_Os_Lock();
    g.tp = fn; g.tp_ctx = ctx;
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29_Core_SetPki(const Uds29_PkiConfigType* p) {
    Uds29_Os_Lock();
    Uds29_Crypto_FreeIdentity(g.ident);
    Uds29_PkiConfigType pc = *p;
    pc.skip_validity_check |= g.vf.policy.time_mode != UDS29_TIME_SYSTEM; /* own certificate: no trusted time either */
    g.ident = Uds29_Crypto_LoadIdentity(&pc, "tester", g.cert, sizeof g.cert, &g.cert_len);
    g.pki_ok = g.ident != NULL;
    bool ok = g.pki_ok;
    Uds29_Os_Unlock();
    return ok ? E_OK : E_NOT_OK;
}

Std_ReturnType Uds29_Core_SetTimeSource(Uds29_TimeSourceFn fn, void* ctx) {
    Uds29_Os_Lock();
    g.vf.time_fn = fn; g.vf.time_ctx = ctx;
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29_Core_SetRevokedSerials(const Uds29_Serial* list, uint16_t count) {
    Uds29_Os_Lock();
    g.vf.revoked = count ? list : NULL; g.vf.n_revoked = list ? count : 0;
    Uds29_Os_Unlock();
    return E_OK;
}

void Uds29_Core_SetEventCallback(Uds29_EventCallback cb) { Uds29_Os_Lock(); g.cb = cb; Uds29_Os_Unlock(); }

Std_ReturnType Uds29_Core_Authenticate(bool bidi) {
    Uds29_Os_Lock();
    Std_ReturnType r = Run(bidi ? OP_AUTH_BI : OP_AUTH_UNI);
    Uds29_Os_Unlock();
    return r;
}

Std_ReturnType Uds29_Core_DeAuthenticate(void) {
    Uds29_Os_Lock();
    Std_ReturnType r = Run(OP_DEAUTH);
    Uds29_Os_Unlock();
    return r;
}

Uds29_StateType Uds29_Core_GetState(void) {
    Uds29_Os_Lock();
    Uds29_StateType s = g.state;
    Uds29_Os_Unlock();
    return s;
}

Std_ReturnType Uds29_Core_SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len) {
    Std_ReturnType r;
    Uds29_Os_Lock();
    if (!g.init || !g.tp) r = E_MODE_INVALID;
    else if (len > UDS29_MAX_MSG_LEN) r = E_NOT_OK;
    else r = Transfer(req, len, resp, resp_len);
    Uds29_Os_Unlock();
    return r;
}

uint32_t Uds29_Core_GetLogCount(void) {
    Uds29_Os_Lock();
    uint32_t n = g.log_count;
    Uds29_Os_Unlock();
    return n;
}

Std_ReturnType Uds29_Core_GetLogEntry(uint32_t i, Uds29_DirectionType* dir, uint8_t* buf, uint16_t cap, uint16_t* len) {
    Std_ReturnType r = E_NOT_OK;
    Uds29_Os_Lock();
    if (i < g.log_count) {
        const LogEntry* e = &g.log[(g.log_head + i) % UDS29_LOG_DEPTH];
        *dir = e->dir;
        *len = e->len < cap ? e->len : cap;
        memcpy(buf, e->data, *len);
        r = E_OK;
    }
    Uds29_Os_Unlock();
    return r;
}

void Uds29_Core_ClearLog(void) {
    Uds29_Os_Lock();
    g.log_head = g.log_count = 0;
    Uds29_Os_Unlock();
}

/* ── Non-blocking API ─────────────────────────────────────────────────────── */
Std_ReturnType Uds29_Core_SetTxCallback(Uds29_TxCallback fn, void* ctx) {
    Uds29_Os_Lock();
    g.txcb = fn; g.txctx = ctx;
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29_Core_Start(int op) {
    Uds29_Os_Lock();
    Std_ReturnType r = g.txcb ? Begin((Op)op) : E_MODE_INVALID;
    Uds29_Os_Unlock();
    return r;
}

void Uds29_Core_MainFunction(void) {
    Uds29_Os_Lock();
    if (g.busy && g.tx_ready) {
        /* State is updated before the callback so it may call RxIndication synchronously (loopback). */
        g.tx_ready = false; g.waiting = true; g.t0 = Now();
        Log(UDS29_DIR_TX, g.tx, g.tx_len);
        if (g.txcb(g.tx, g.tx_len, g.txctx) != E_OK && g.busy) (void)Fail(g.cur_sub, "tx callback failed", 0);
    } else if (g.busy && g.waiting && (uint32_t)(Now() - g.t0) >= UDS29_P2_TIMEOUT_MS) {
        (void)Fail(g.cur_sub, "response timeout", 0);
    }
    Uds29_Os_Unlock();
}

Std_ReturnType Uds29_Core_RxIndication(const uint8_t* resp, uint16_t len) {
    Std_ReturnType r = E_NOT_OK; /* ponytail: oversize/stray frames are rejected, the pending request keeps its timeout */
    Uds29_Os_Lock();
    if (g.busy && g.waiting && len <= UDS29_MAX_MSG_LEN) {
        g.waiting = false;
        Log(UDS29_DIR_RX, resp, len);
        (void)OnResponse(resp, len); /* outcome is reported through state and events */
        r = E_OK;
    }
    Uds29_Os_Unlock();
    return r;
}

void Uds29_Core_SetClockForTest(uint32_t (*fn)(void)) { Uds29_Os_Lock(); g.clock = fn; Uds29_Os_Unlock(); }
