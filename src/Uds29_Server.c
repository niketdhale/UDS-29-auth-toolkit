/* ECU-side session handler for SID 0x29. All state is static; every entry point takes the recursive OS lock
   (event callbacks run with it held and may call back into the API). */
#include "Uds29_Server.h"
#include "Uds29_ServerTest.h"
#include "Uds29_Cfg.h"
#include "Uds29_Codec.h"
#include "Uds29_Crypto.h"
#include "Uds29_Os.h"
#include "Uds29_Policy.h"
#include <string.h>
#include <time.h>

static struct {
    bool                init;
    Uds29Srv_ConfigType cfg;
    Uds29_Verifier      vf;                 /* policy, time source, revoked serials for the tester certificate */
    void*               ident;
    uint8_t             cert[UDS29_MAX_CERT_LEN];
    uint16_t            cert_len;
    Uds29_StateType     state;
    uint32_t            t0;                 /* when the current state was entered */
    Uds29_EventCallback cb;
    Uds29_Authz         authz;              /* of the client whose certificate was accepted; zero when IDLE */
    Uds29Srv_AuthzParser parser;
    void*               parser_ctx;
    const Uds29Srv_AccessRule* rules;
    uint16_t            nrules;
    uint8_t             client_cert[UDS29_MAX_CERT_LEN];
    uint16_t            client_cert_len;
    uint8_t             challenge[UDS29_MAX_CHALLENGE_LEN];
    uint8_t             challenge_len;
    uint8_t             client_challenge[UDS29_MAX_CHALLENGE_LEN]; /* sent with 0x01/0x02, part of the proof-of-ownership data */
    uint8_t             client_challenge_len, comm;
    bool                bidi;
    Uds29Srv_Fault      fault;
    uint8_t             forced_nrc;
    uint16_t            failed;             /* counted certificate / proof failures */
    bool                locked;
    uint32_t            lock_t0;
    uint32_t          (*clock)(void);       /* test hook, NULL = Uds29_Os_GetTimeMs */
    Uds29_Req           rq;                 /* scratch, kept off the stack */
    Uds29_Resp          rs;
} g;

static uint32_t Now(void) { return g.clock ? g.clock() : Uds29_Os_GetTimeMs(); }

static void Emit(Uds29_EventKindType k, uint8_t sub, uint8_t nrc, const char* why) {
    if (!g.cb) return;
    Uds29_EventType e = {k, g.state, sub, nrc, why};
    g.cb(&e);
}

static void SetState(Uds29_StateType s) {
    if (s == g.state) return;
    g.state = s;
    if (s == UDS29_STATE_IDLE) memset(&g.authz, 0, sizeof g.authz);
    g.t0 = Now();
    Emit(UDS29_EVT_STATE_CHANGE, 0, 0, "");
}

/* Auth timeout: back to unauthenticated. */
static void Expire(void) {
    if (g.cfg.auth_timeout_ms && g.state != UDS29_STATE_IDLE &&
        (uint32_t)(Now() - g.t0) >= g.cfg.auth_timeout_ms) {
        SetState(UDS29_STATE_IDLE);
        Emit(UDS29_EVT_FAILURE, 0, 0, "authentication timeout");
    }
}

/* ── response builders ── */
static Std_ReturnType Out(uint8_t* resp, uint16_t* cap) {
    uint16_t n = Uds29_Codec_EncodeResponse(&g.rs, resp, *cap);
    if (n == 0) return E_NOT_OK;
    *cap = n;
    return E_OK;
}

/* Negative response; `reset` also drops a pending/finished authentication (rejected certificate or proof). */
static Std_ReturnType Neg(uint8_t sub, uint8_t nrc, bool reset, uint8_t* resp, uint16_t* cap) {
    const char* why = Uds29_Codec_NrcToString(nrc);
    if (g.cfg.max_failed_attempts && nrc >= UDS29_NRC_CVF_INVALID_TIME_PERIOD && nrc <= UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED &&
        ++g.failed >= g.cfg.max_failed_attempts) {
        nrc = UDS29_NRC_EXCEEDED_NUMBER_OF_ATTEMPTS; why = "attempts exceeded";
        g.locked = true; g.lock_t0 = Now();
    } else if (nrc == UDS29_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED) why = "lockout";
    if (reset) SetState(UDS29_STATE_IDLE);
    Emit(UDS29_EVT_FAILURE, sub, nrc, why);
    memset(&g.rs, 0, sizeof g.rs);
    g.rs.neg = true; g.rs.nrc = nrc;
    return Out(resp, cap);
}

/* Data signed for `verifier` (the other party's certificate; see Uds29_PownFormat): by the ECU in the 0x02 response, by the tester in 0x03. */
static bool Pown(bool ecu_signs, const uint8_t* verifier, uint16_t verifier_len, uint8_t* out, uint16_t cap, uint16_t* n) {
    Uds29_PownIn in;
    memset(&in, 0, sizeof in);
    in.server_ch = g.challenge; in.server_len = g.challenge_len;
    in.client_ch = g.client_challenge; in.client_len = g.client_challenge_len;
    in.own_cert = ecu_signs ? g.cert : verifier;   in.own_len = ecu_signs ? g.cert_len : verifier_len;
    in.peer_cert = ecu_signs ? verifier : g.cert;  in.peer_len = ecu_signs ? verifier_len : g.cert_len;
    in.comm = g.comm; in.bidi = g.bidi;
    in.raw = ecu_signs ? g.client_challenge : g.challenge;          /* the challenge issued by the verifier */
    in.raw_len = ecu_signs ? g.client_challenge_len : g.challenge_len;
    return Uds29_Pown_Build(&g.cfg.pown, &in, out, cap, n);
}

/* Server NRC for a failed peer-certificate check (see docs/certificate-validation.md); nrc_collapse = the 0.5.0 values. */
static uint8_t PkiNrc(Uds29_PkiResult r) {
    uint8_t n;
    switch (r) {
    case UDS29_PKI_PARSE:   return UDS29_NRC_CVF_INVALID_FORMAT;
    case UDS29_PKI_EXPIRED:
    case UDS29_PKI_TIME_UNTRUSTED: return UDS29_NRC_CVF_INVALID_TIME_PERIOD;
    case UDS29_PKI_SIGNATURE: n = UDS29_NRC_CVF_INVALID_SIGNATURE; break;
    case UDS29_PKI_REVOKED: n = UDS29_NRC_CVF_INVALID_CERTIFICATE; break;
    case UDS29_PKI_POLICY:
    case UDS29_PKI_POLICY_USAGE:
    case UDS29_PKI_POLICY_ALG: n = UDS29_NRC_CVF_INVALID_TYPE; break;
    default: return UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST;
    }
    if (g.cfg.nrc_collapse) n = n == UDS29_NRC_CVF_INVALID_TYPE ? UDS29_NRC_CVF_INVALID_SCOPE : UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST;
    return n;
}

static Std_ReturnType VerifyCert(uint8_t* resp, uint16_t* cap) {
    const Uds29_Req* rq = &g.rq;
    if (g.cfg.supported_comm_config_mask && (rq->comm > 7 || !(g.cfg.supported_comm_config_mask & (1u << rq->comm))))
        return Neg(rq->sub, UDS29_NRC_CONFIGURATION_DATA_USAGE_FAILED, true, resp, cap);
    if (g.fault == UDS29SRV_FAULT_WRONG_CERT_FORMAT && rq->sub == UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL)
        return Neg(rq->sub, UDS29_NRC_CVF_INVALID_FORMAT, true, resp, cap);
    int64_t at = g.fault == UDS29SRV_FAULT_EXPIRED_CERT ? (int64_t)time(NULL) + 11LL * 365 * 86400 : 0;
    bool skipped;
    Uds29_PkiResult vr = Uds29_Verifier_Check(&g.vf, g.ident, rq->cert, rq->cert_len, at, &skipped);
    if (skipped) Emit(UDS29_EVT_WARNING, rq->sub, 0, "validity not checked");
    if (vr != UDS29_PKI_OK) return Neg(rq->sub, PkiNrc(vr), true, resp, cap);
    Uds29_Authz az;
    memset(&az, 0, sizeof az);
    Std_ReturnType pr = g.parser ? g.parser(rq->cert, rq->cert_len, &az, g.parser_ctx)
                      : g.cfg.profile ? Uds29_Authz_FromCert(g.cfg.profile, rq->cert, rq->cert_len, &az) : E_OK;
    if (pr != E_OK || az.n_services > UDS29_MAX_ALLOW || az.n_dids > UDS29_MAX_ALLOW || az.n_rids > UDS29_MAX_ALLOW)
        return Neg(rq->sub, UDS29_NRC_CVF_INVALID_CONTENT, true, resp, cap);
    if (g.cfg.required_roles && !(az.roles & g.cfg.required_roles))
        return Neg(rq->sub, UDS29_NRC_CVF_INVALID_SCOPE, true, resp, cap);
    g.authz = az;
    memcpy(g.client_cert, rq->cert, rq->cert_len);
    g.client_cert_len = rq->cert_len;
    memcpy(g.client_challenge, rq->challenge, rq->challenge_len);
    g.client_challenge_len = (uint8_t)rq->challenge_len;
    g.comm = rq->comm;
    g.bidi = rq->sub == UDS29_SF_VERIFY_CERT_BIDIRECTIONAL;
    if (Uds29_Crypto_Random(g.challenge, g.challenge_len) != E_OK)
        return Neg(rq->sub, UDS29_NRC_CHALLENGE_CALCULATION_FAILED, true, resp, cap);

    memset(&g.rs, 0, sizeof g.rs);
    g.rs.sub = rq->sub;
    g.rs.ret = UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY;
    memcpy(g.rs.challenge, g.challenge, g.challenge_len);
    g.rs.challenge_len = g.challenge_len;
    if (rq->sub == UDS29_SF_VERIFY_CERT_BIDIRECTIONAL) {   /* prove the ECU's identity over the client's challenge */
        uint8_t data[UDS29_POWN_DATA_MAX];
        uint16_t n;
        if (!Pown(true, rq->cert, rq->cert_len, data, sizeof data, &n))
            return Neg(rq->sub, UDS29_NRC_CHALLENGE_CALCULATION_FAILED, true, resp, cap);
        if (g.fault == UDS29SRV_FAULT_CHALLENGE_MISMATCH) data[n++] = 0xFF;
        if (g.fault == UDS29SRV_FAULT_WRONG_CERT_FORMAT) { memcpy(g.rs.cert, "\xDE\xAD\xBE\xEF", 4); g.rs.cert_len = 4; }
        else { memcpy(g.rs.cert, g.cert, g.cert_len); g.rs.cert_len = g.cert_len; }
        if (Uds29_Crypto_Sign(g.ident, data, n, g.rs.pown, sizeof g.rs.pown, &g.rs.pown_len) != E_OK)
            return Neg(rq->sub, UDS29_NRC_CHALLENGE_CALCULATION_FAILED, true, resp, cap);
        if (g.fault == UDS29SRV_FAULT_BAD_SIGNATURE && g.rs.pown_len) g.rs.pown[g.rs.pown_len - 1] ^= 0x01;
    }
    Std_ReturnType r = Out(resp, cap);
    if (r == E_OK) { if (g.state == UDS29_STATE_CERT_SENT) g.t0 = Now(); else SetState(UDS29_STATE_CERT_SENT); }
    return r;
}

static Std_ReturnType VerifyPown(uint8_t* resp, uint16_t* cap) {
    const Uds29_Req* rq = &g.rq;
    if (g.state != UDS29_STATE_CERT_SENT) return Neg(rq->sub, UDS29_NRC_REQUEST_SEQUENCE_ERROR, false, resp, cap);
    uint8_t sig[UDS29_MAX_SIG_LEN], exp[UDS29_POWN_DATA_MAX];
    uint16_t sn = rq->pown_len, en;
    memcpy(sig, rq->pown, sn);
    if (!Pown(false, g.client_cert, g.client_cert_len, exp, sizeof exp, &en))
        return Neg(rq->sub, UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED, true, resp, cap);
    if (g.fault == UDS29SRV_FAULT_BAD_SIGNATURE && sn) sig[sn - 1] ^= 0x01;
    if (g.fault == UDS29SRV_FAULT_CHALLENGE_MISMATCH) exp[en++] = 0xFF;
    if (sn == 0 || Uds29_Crypto_Verify(g.client_cert, g.client_cert_len, exp, en, sig, sn) != E_OK)
        return Neg(rq->sub, UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED, true, resp, cap);
    memset(&g.rs, 0, sizeof g.rs);
    g.rs.sub = rq->sub;
    g.rs.ret = UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE;
    Std_ReturnType r = Out(resp, cap);
    if (r == E_OK) { g.failed = 0; SetState(UDS29_STATE_AUTHENTICATED); }
    return r;
}

static Std_ReturnType Handle(const uint8_t* d, uint16_t n, uint8_t* resp, uint16_t* cap) {
    if (n < 2 || d[0] != UDS29_SID_REQUEST) return Neg(0, UDS29_NRC_INCORRECT_LENGTH, false, resp, cap);
    if (d[1] > UDS29_SF_AUTHENTICATION_CONFIGURATION || (d[1] >= UDS29_SF_TRANSMIT_CERTIFICATE && d[1] <= UDS29_SF_VERIFY_POWN_BIDIRECTIONAL))
        return Neg(d[1], UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED, false, resp, cap); /* before decoding: length is moot */
    if (!Uds29_Codec_DecodeRequest(d, n, &g.rq)) /* also: a field above the core's buffer sizes */
        return Neg(d[1], UDS29_NRC_INCORRECT_LENGTH, false, resp, cap);
    if (g.fault == UDS29SRV_FAULT_FORCE_NRC) return Neg(g.rq.sub, g.forced_nrc, false, resp, cap);
    if (g.locked && g.rq.sub >= UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL && g.rq.sub <= UDS29_SF_PROOF_OF_OWNERSHIP) {
        if ((uint32_t)(Now() - g.lock_t0) >= g.cfg.lockout_delay_ms) { g.locked = false; g.failed = 0; }
        else return Neg(g.rq.sub, UDS29_NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED, false, resp, cap);
    }

    switch (g.rq.sub) {
    case UDS29_SF_DEAUTHENTICATE:
        memset(&g.rs, 0, sizeof g.rs);
        g.rs.sub = g.rq.sub; g.rs.ret = UDS29_RET_DEAUTHENTICATION_SUCCESSFUL;
        SetState(UDS29_STATE_IDLE);
        return Out(resp, cap);
    case UDS29_SF_AUTHENTICATION_CONFIGURATION:
        memset(&g.rs, 0, sizeof g.rs);
        g.rs.sub = g.rq.sub; g.rs.ret = UDS29_RET_AUTH_CONFIG_APCE;
        return Out(resp, cap);
    case UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL:
    case UDS29_SF_VERIFY_CERT_BIDIRECTIONAL:
        return VerifyCert(resp, cap);
    case UDS29_SF_PROOF_OF_OWNERSHIP:
        return VerifyPown(resp, cap);
    default: /* not reachable: filtered above */
        return Neg(g.rq.sub, UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED, false, resp, cap);
    }
}

/* ── API ── */
Std_ReturnType Uds29Srv_Init(const Uds29Srv_ConfigType* c) {
    if (!c) return E_PARAM_POINTER;
    if (c->challenge_len > UDS29_MAX_CHALLENGE_LEN) return E_NOT_OK;
    Uds29_Os_Lock();
    Uds29_Crypto_FreeIdentity(g.ident);
    memset(&g.cfg, 0, sizeof g.cfg);
    g.cfg = *c;
    g.vf.policy = c->policy;
    g.challenge_len = c->challenge_len ? c->challenge_len : 32;
    if (g.challenge_len > UDS29_MAX_CHALLENGE_LEN) g.challenge_len = UDS29_MAX_CHALLENGE_LEN;
    Uds29_PkiConfigType pc = c->pki;
    pc.skip_validity_check |= c->policy.time_mode != UDS29_TIME_SYSTEM; /* own certificate: no trusted time either */
    g.ident = Uds29_Crypto_LoadIdentity(&pc, "ecu", g.cert, sizeof g.cert, &g.cert_len);
    g.init = g.ident != NULL;
    g.state = UDS29_STATE_IDLE;
    g.failed = 0; g.locked = false;
    memset(&g.authz, 0, sizeof g.authz);
    Uds29_Os_Unlock();
    return g.init ? E_OK : E_NOT_OK;
}

Std_ReturnType Uds29Srv_DeInit(void) {
    Uds29_Os_Lock();
    Uds29_Crypto_FreeIdentity(g.ident);
    g.ident = NULL; g.init = false; g.cb = NULL; g.cert_len = g.client_cert_len = 0;
    g.parser = NULL; g.parser_ctx = NULL; g.rules = NULL; g.nrules = 0;
    g.state = UDS29_STATE_IDLE;
    memset(&g.authz, 0, sizeof g.authz);
    g.fault = UDS29SRV_FAULT_NONE;
    memset(&g.vf, 0, sizeof g.vf);
    Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29Srv_HandleRequest(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len) {
    if (!req || !resp || !resp_len) return E_PARAM_POINTER;
    Uds29_Os_Lock();
    Std_ReturnType r = E_MODE_INVALID;
    if (g.init) {
        Expire();
        r = Handle(req, len, resp, resp_len);
    }
    Uds29_Os_Unlock();
    return r;
}

void Uds29Srv_MainFunction(void) {
    Uds29_Os_Lock();
    if (g.init) Expire();
    Uds29_Os_Unlock();
}

Uds29_StateType Uds29Srv_GetState(void) {
    Uds29_Os_Lock();
    Uds29_StateType s = g.state;
    Uds29_Os_Unlock();
    return s;
}

uint16_t Uds29Srv_GetFailedAttempts(void) {
    Uds29_Os_Lock(); uint16_t n = g.failed; Uds29_Os_Unlock();
    return n;
}

void Uds29Srv_ResetLockout(void) { Uds29_Os_Lock(); g.failed = 0; g.locked = false; Uds29_Os_Unlock(); }

bool Uds29Srv_IsAuthenticated(void) { return Uds29Srv_GetState() == UDS29_STATE_AUTHENTICATED; }

/* ── access control ── */
Std_ReturnType Uds29Srv_SetTimeSource(Uds29_TimeSourceFn fn, void* ctx) {
    Uds29_Os_Lock(); g.vf.time_fn = fn; g.vf.time_ctx = ctx; Uds29_Os_Unlock();
    return E_OK;
}

Std_ReturnType Uds29Srv_SetRevokedSerials(const Uds29_Serial* list, uint16_t count) {
    Uds29_Os_Lock(); g.vf.revoked = count ? list : NULL; g.vf.n_revoked = list ? count : 0; Uds29_Os_Unlock();
    return E_OK;
}

void Uds29Srv_SetAuthzParser(Uds29Srv_AuthzParser fn, void* ctx) { Uds29_Os_Lock(); g.parser = fn; g.parser_ctx = ctx; Uds29_Os_Unlock(); }

void Uds29Srv_SetAccessRules(const Uds29Srv_AccessRule* rules, uint16_t count) {
    Uds29_Os_Lock();
    g.rules = count ? rules : NULL;
    g.nrules = rules ? count : 0;
    Uds29_Os_Unlock();
}

Std_ReturnType Uds29Srv_GetAuthz(Uds29_Authz* out) {
    if (!out) return E_PARAM_POINTER;
    Uds29_Os_Lock();
    bool ok = g.state == UDS29_STATE_AUTHENTICATED;
    if (ok) *out = g.authz; else memset(out, 0, sizeof *out);
    Uds29_Os_Unlock();
    return ok ? E_OK : E_NOT_OK;
}

static uint16_t Be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

/* The identifiers a request refers to (see Uds29_Server.h): how many, and the k-th one. */
static uint16_t IdCount(const uint8_t* r, uint16_t n) { return (r[0] == 0x22 && n >= 3) ? (uint16_t)((n - 1) / 2) : 1; }
static uint16_t IdAt(const uint8_t* r, uint16_t n, uint16_t k) {
    switch (r[0]) {
    case 0x22: return n >= 3 ? Be16(r + 1 + 2 * k) : UDS29_ANY;
    case 0x2E: return n >= 3 ? Be16(r + 1) : UDS29_ANY;
    case 0x31: return n >= 4 ? Be16(r + 2) : UDS29_ANY;
    case 0x10: case 0x11: case 0x27: case 0x28: case 0x85: return n >= 2 ? (uint16_t)(r[1] & 0x7F) : UDS29_ANY;
    default:   return UDS29_ANY;
    }
}

static bool RuleGrants(uint8_t sid, uint16_t id) {
    for (uint16_t i = 0; i < g.nrules; i++) {
        const Uds29Srv_AccessRule* r = &g.rules[i];
        if (r->sid == sid && (r->sub_or_id == UDS29_ANY || r->sub_or_id == id) && (!r->roles || (g.authz.roles & r->roles)))
            return true;
    }
    return false;
}

static bool InList16(const uint16_t* l, uint8_t n, uint16_t v) { while (n--) if (*l++ == v) return true; return false; }

static bool CertAllows(const uint8_t* req, uint16_t len) {
    const Uds29_Authz* a = &g.authz;
    uint8_t sid = req[0];
    bool found = false;
    for (uint8_t i = 0; i < a->n_services; i++) found |= a->services[i] == sid;
    if (a->n_services && !found) return false;
    const uint16_t* l = sid == 0x31 ? a->rids : a->dids;
    uint8_t n = sid == 0x31 ? a->n_rids : (sid == 0x22 || sid == 0x2E) ? a->n_dids : 0;
    for (uint16_t k = 0; n && k < IdCount(req, len); k++) if (!InList16(l, n, IdAt(req, len, k))) return false;
    return true;
}

Std_ReturnType Uds29Srv_CheckAccess(const uint8_t* req, uint16_t len, uint8_t* nrc) {
    if (!req || !nrc) return E_PARAM_POINTER;
    if (len == 0) { *nrc = UDS29_NRC_INCORRECT_LENGTH; return E_NOT_OK; }
    Uds29_Os_Lock();
    uint8_t sid = req[0];
    bool ok = true;
    if (sid != UDS29_SID_REQUEST && sid != 0x3E) {
        bool auth = g.state == UDS29_STATE_AUTHENTICATED, listed = false;
        for (uint16_t i = 0; i < g.nrules; i++) listed |= g.rules[i].sid == sid;
        if (listed || g.cfg.deny_unlisted_sid) {
            ok = auth && listed;
            for (uint16_t k = 0; ok && k < IdCount(req, len); k++) ok = RuleGrants(sid, IdAt(req, len, k));
        }
        if (ok && auth) ok = CertAllows(req, len); /* the certificate may narrow further */
        if (!ok) {
            *nrc = g.cfg.deny_nrc ? g.cfg.deny_nrc : UDS29_NRC_AUTHENTICATION_REQUIRED;
            Emit(UDS29_EVT_FAILURE, 0, *nrc, "access denied");
        }
    }
    Uds29_Os_Unlock();
    return ok ? E_OK : E_NOT_OK;
}

void Uds29Srv_SetEventCallback(Uds29_EventCallback cb) { Uds29_Os_Lock(); g.cb = cb; Uds29_Os_Unlock(); }

void Uds29Srv_SetFaultForTest(Uds29Srv_Fault f, uint8_t nrc) { Uds29_Os_Lock(); g.fault = f; g.forced_nrc = nrc; Uds29_Os_Unlock(); }
void Uds29Srv_SetClockForTest(uint32_t (*fn)(void)) { Uds29_Os_Lock(); g.clock = fn; Uds29_Os_Unlock(); }
