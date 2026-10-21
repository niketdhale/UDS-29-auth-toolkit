#include "Uds29.h"
#include "Uds29_SimEcu.h"
#include "Uds29_Server.h"
#include "access_example.h"
#include "Uds29_Der.h"
#include <cstring>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifdef UDS29_WITH_IDSM
#include "Uds29_IdsM.h"
#include "IdsM.h"
#endif

static const char* kStates[] = {"IDLE", "CERT_SENT", "CHALLENGE_RECEIVED", "POWN_SENT", "AUTHENTICATED", "FAILED"};

static std::string Hex(const uint8_t* p, size_t n) {
    std::string s; char b[4];
    for (size_t i = 0; i < n; i++) { std::snprintf(b, sizeof b, i ? " %02X" : "%02X", p[i]); s += b; }
    return s;
}

/* Accepts "29 01", "2901", "0x29,0x01"; returns false on odd/invalid digits. */
static bool ParseHex(std::string s, Uds29_Bytes& out) {
    std::string d;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '0' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) { i++; continue; }
        if (std::isspace((unsigned char)s[i]) || s[i] == ',') continue;
        if (!std::isxdigit((unsigned char)s[i])) return false;
        d += s[i];
    }
    if (d.empty() || d.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < d.size(); i += 2) out.push_back((uint8_t)std::stoi(d.substr(i, 2), nullptr, 16));
    return true;
}

static void Decode(const Uds29_Bytes& b) {
    static Uds29_Req rq; static Uds29_Resp rs; /* large structs: keep off the stack */
    if (Uds29_Codec_DecodeRequest(b.data(), b.size(), &rq)) {
        std::printf("request sub=0x%02X comm=0x%02X eval=0x%04X cert=%uB challenge=%uB pown=%uB eph=%uB addl=%uB\n",
                    rq.sub, rq.comm, rq.eval_id, rq.cert_len, rq.challenge_len, rq.pown_len, rq.eph_len, rq.addl_len);
    } else if (Uds29_Codec_DecodeResponse(b.data(), b.size(), &rs)) {
        if (rs.neg) std::printf("negative response nrc=0x%02X (%s)\n", rs.nrc, Uds29_Codec_NrcToString(rs.nrc));
        else std::printf("positive response sub=0x%02X ret=0x%02X (%s) cert=%uB challenge=%uB pown=%uB eph=%uB session_key=%uB\n",
                         rs.sub, rs.ret, Uds29_Codec_ReturnParamToString(rs.ret), rs.cert_len, rs.challenge_len,
                         rs.pown_len, rs.eph_len, rs.session_key_len);
    } else std::puts("[ERR] not a valid SID 0x29 request or response (or a field exceeds the UDS29_MAX_* buffer sizes)");
}


/* ── certificate inspection ── */
static bool LoadCert(const std::string& path, bool der, Uds29_Bytes& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    out.clear();
    if (der) { out.assign(raw.begin(), raw.end()); return !out.empty(); }
    size_t b = raw.find("-----BEGIN CERTIFICATE-----"), e = raw.find("-----END CERTIFICATE-----");
    if (b == std::string::npos || e == std::string::npos) return false;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = b + 27; i < e; i++) {
        const char* t = std::strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", raw[i]);
        if (!t || !raw[i]) continue;                 /* skips newlines and '=' */
        acc = (acc << 6) | (uint32_t)(t - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        if ((bits += 6) >= 8) { bits -= 8; out.push_back((uint8_t)(acc >> bits)); }
    }
    return !out.empty();
}

static std::string Dotted(const uint8_t* v, size_t n) {
    std::string s; uint32_t x = 0;
    for (size_t i = 0; i < n; i++) {
        x = (x << 7) | (v[i] & 0x7F);
        if (v[i] & 0x80) continue;
        if (s.empty()) s = std::to_string(x / 40 > 2 ? 2 : x / 40) + "." + std::to_string(x - 40 * (x / 40 > 2 ? 2 : x / 40));
        else s += "." + std::to_string(x);
        x = 0;
    }
    return s;
}

/* RDNSequence -> "CN=..., OU=..." */
static std::string Name(const uint8_t* v, size_t n) {
    static const struct { const char* oid; const char* name; } kN[] = {
        {"2.5.4.3", "CN"}, {"2.5.4.6", "C"}, {"2.5.4.7", "L"}, {"2.5.4.8", "ST"}, {"2.5.4.10", "O"}, {"2.5.4.11", "OU"}};
    std::string out;
    const uint8_t *p = v, *end = v + n, *rv, *av, *ov, *sv;
    uint8_t t, at, ot, st; size_t rl, al, ol, sl;
    while (Uds29_Der_Tlv(&p, end, &t, &rv, &rl)) {
        const uint8_t* a = rv;
        while (Uds29_Der_Tlv(&a, rv + rl, &at, &av, &al)) {
            const uint8_t* q = av;
            if (!Uds29_Der_Tlv(&q, av + al, &ot, &ov, &ol) || !Uds29_Der_Tlv(&q, av + al, &st, &sv, &sl)) continue;
            std::string o = Dotted(ov, ol), nm = o;
            for (auto& k : kN) if (o == k.oid) nm = k.name;
            out += (out.empty() ? "" : ", ") + nm + "=" + std::string((const char*)sv, sl);
        }
    }
    return out;
}

static std::string Time(const uint8_t* v, size_t n, uint8_t tag) {
    std::string d((const char*)v, n);
    if (tag == 0x17 && n >= 12) d = (d[0] < '5' ? "20" : "19") + d;       /* UTCTime YYMMDDHHMMSSZ */
    if (d.size() < 14) return d;
    return d.substr(0, 4) + "-" + d.substr(4, 2) + "-" + d.substr(6, 2) + " " + d.substr(8, 2) + ":" + d.substr(10, 2) + ":" + d.substr(12, 2);
}

/* The PKI of the last `pki sample` / `pki load`: certificates are verified against it (intermediates and CRLs included). */
struct LoadedPki {
    bool set = false;
    Uds29_PkiConfigType cfg{};
    std::string ca, cert, key;
    std::vector<std::string> inter, crl;
    void Bind() {                       /* cfg points into the strings above: call after the strings are final */
        for (size_t i = 0; i < inter.size(); i++) cfg.intermediate_paths[i] = inter[i].c_str();
        for (size_t i = 0; i < crl.size(); i++) cfg.crl_paths[i] = crl[i].c_str();
        cfg.root_ca_path = ca.c_str(); cfg.cert_path = cert.c_str(); cfg.key_path = key.c_str();
    }
};
static LoadedPki g_pki;

static const char* kKu[] = {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
                            "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};

static void InspectPolicyFields(const Uds29_Bytes& c) {
    Uds29_DerCert d;
    if (!Uds29_Der_ParseCert(c.data(), c.size(), &d)) return;
    unsigned kt = Uds29_Der_KeyType(&d), sa = Uds29_Der_SigAlg(&d), ku;
    std::printf("serial:  %s\n", Hex(d.serial, d.serial_len).c_str());
    std::printf("key:     %s\n", kt == UDS29_KEY_EC_P256 ? "EC P-256" : kt == UDS29_KEY_EC_P384 ? "EC P-384" : kt == UDS29_KEY_ED25519 ? "Ed25519" : "other / unsupported");
    std::printf("sig alg: %s\n", sa == UDS29_SIG_ECDSA_SHA256 ? "ecdsa-with-SHA256" : sa == UDS29_SIG_ECDSA_SHA384 ? "ecdsa-with-SHA384"
                                  : sa == UDS29_SIG_ED25519 ? "Ed25519" : ("other " + Dotted(d.sigalg, d.sigalg_len)).c_str());
    std::printf("keyUsage:");
    if (Uds29_Der_KeyUsage(&d, &ku)) { for (unsigned i = 0; i < 9; i++) if (ku & (0x8000u >> i)) std::printf(" %s", kKu[i]); std::puts(""); }
    else std::puts(" (none)");
    std::printf("EKU:    ");
    const uint8_t* l; size_t n;
    if (Uds29_Der_Eku(&d, &l, &n)) {
        const uint8_t* v; size_t vl; uint8_t t;
        for (const uint8_t* q = l; Uds29_Der_Tlv(&q, l + n, &t, &v, &vl); ) std::printf(" %s", Dotted(v, vl).c_str());
        std::puts("");
    } else std::puts(" (none)");
}

static void InspectChain(const Uds29_Bytes& c) {
    if (!g_pki.set) { std::puts("chain:   (no PKI loaded: pki sample | pki load ...)"); return; }
    static uint8_t own[UDS29_MAX_CERT_LEN]; uint16_t n = 0;
    void* id = Uds29_Crypto_LoadIdentity(&g_pki.cfg, "tester", own, sizeof own, &n);
    if (!id) { std::puts("chain:   (cannot load the loaded PKI as an identity)"); return; }
    static const char* kR[] = {"OK", "unparsable", "expired / not yet valid", "chain of trust invalid", "REVOKED", "policy", "no trusted time"};
    Uds29_PkiResult r = Uds29_Crypto_VerifyPeer(id, c.data(), (uint16_t)c.size(), 0);
    std::printf("chain:   %s (root %s, %zu intermediate(s), %zu CRL(s))\n", kR[r], g_pki.ca.empty() ? "sample" : g_pki.ca.c_str(),
                g_pki.inter.size(), g_pki.crl.size());
    Uds29_Crypto_FreeIdentity(id);
}

static void InspectCert(const Uds29_Bytes& c) {
    const uint8_t *p = c.data(), *end = p + c.size(), *v;
    uint8_t t; size_t l;
    std::string subject, issuer, nb, na;
    bool ok = Uds29_Der_Tlv(&p, end, &t, &v, &l) && t == 0x30;
    if (ok) { p = v; end = v + l; ok = Uds29_Der_Tlv(&p, end, &t, &v, &l) && t == 0x30; }   /* TBSCertificate */
    if (ok) {
        p = v; end = v + l;
        ok = Uds29_Der_Tlv(&p, end, &t, &v, &l);
        if (ok && t == 0xA0) ok = Uds29_Der_Tlv(&p, end, &t, &v, &l);                       /* version, serial */
        ok = ok && Uds29_Der_Tlv(&p, end, &t, &v, &l);                                      /* signature algorithm */
        ok = ok && Uds29_Der_Tlv(&p, end, &t, &v, &l);                                      /* issuer */
        if (ok) issuer = Name(v, l);
        ok = ok && Uds29_Der_Tlv(&p, end, &t, &v, &l);                                      /* validity */
        if (ok) {
            const uint8_t *q = v, *tv; uint8_t tt; size_t tl;
            if (Uds29_Der_Tlv(&q, v + l, &tt, &tv, &tl)) nb = Time(tv, tl, tt);
            if (Uds29_Der_Tlv(&q, v + l, &tt, &tv, &tl)) na = Time(tv, tl, tt);
        }
        ok = ok && Uds29_Der_Tlv(&p, end, &t, &v, &l);                                      /* subject */
        if (ok) subject = Name(v, l);
    }
    if (!ok) { std::puts("[ERR] not a valid X.509 certificate"); return; }
    std::printf("subject: %s\nissuer:  %s\nvalid:   %s .. %s UTC\n", subject.c_str(), issuer.c_str(), nb.c_str(), na.c_str());
    InspectPolicyFields(c);
    InspectChain(c);
    Uds29_Authz a;
    if (Uds29_Authz_FromCert(&kExampleProfile, c.data(), (uint16_t)c.size(), &a) != E_OK) {
        std::puts("authz:   MALFORMED value for the example profile");
        return;
    }
    std::printf("authz (example profile 1.3.6.1.4.1.99999.29.x): roles=0x%08X", a.roles);
    if (a.roles & EX_ROLE_WORKSHOP) std::printf(" workshop");
    if (a.roles & EX_ROLE_ENGINEERING) std::printf(" engineering");
    if (a.roles & EX_ROLE_OEM) std::printf(" oem");
    std::printf("\n  services: ");
    for (unsigned i = 0; i < a.n_services; i++) std::printf("%02X ", a.services[i]);
    std::printf("%s\n  dids:     ", a.n_services ? "" : "(any)");
    for (unsigned i = 0; i < a.n_dids; i++) std::printf("%04X ", a.dids[i]);
    std::printf("%s\n  rids:     ", a.n_dids ? "" : "(any)");
    for (unsigned i = 0; i < a.n_rids; i++) std::printf("%04X ", a.rids[i]);
    std::printf("%s\n", a.n_rids ? "" : "(any)");
}

static void CertCommand(const std::string& a, const std::string& rest) {
    std::istringstream r(rest);
    std::string file, fmt;
    r >> file >> fmt;
    Uds29_Bytes c;
    if (a != "inspect" || file.empty()) { std::puts("[ERR] cert inspect <file> [der]"); return; }
    if (!LoadCert(file, fmt == "der", c)) { std::puts("[ERR] cannot read certificate (PEM; add 'der' for DER)"); return; }
    InspectCert(c);
}

static void OnEvent(const Uds29_EventType* e) {
    if (e->kind == UDS29_EVT_STATE_CHANGE) std::printf("  [event] state -> %s\n", kStates[e->state]);
    else if (e->kind == UDS29_EVT_WARNING) std::printf("  [event] WARNING sub=0x%02X %s\n", e->sub_function, e->description);
    else std::printf("  [event] FAILURE sub=0x%02X nrc=0x%02X %s\n", e->sub_function, e->nrc, e->description);
#ifdef UDS29_WITH_IDSM
    Uds29_IdsM_OnEvent(e);
#endif
}
#ifdef UDS29_WITH_IDSM
static std::atomic<unsigned> g_dem{0};
static std::atomic<int> g_last_sev{-1};
static std::atomic<unsigned> g_last_id{0};
static void OnDem(const IdsM_EventReportType* r) { g_dem++; g_last_sev = r->severity; g_last_id = r->event_id; }
#endif

static void Help() {
    std::puts("Commands: help, pki sample | pki load <ca> <cert> <key> [der] [--inter f]... [--crl f]...,\n"
              "          auth uni|bi, deauth, send <hex>, decode <hex>, cert inspect <file> [der],\n"
              "          inject <none|expired|badsig|mismatch|wrongfmt|nrc <hex>>,\n"
              "          status, log, clear"
#ifdef UDS29_WITH_IDSM
              ", idsm status"
#endif
              ", quit");
}

/* --role server: stdin = hex requests, stdout = hex responses (one per line), ECU identity from the sample PKI
   or --ca/--cert/--key. The example access rules and certificate profile (examples/access_example.h) are active.
   Extra commands: access <hex> (policy check of a request), login <cert.pem> <key.pem> (authenticate a tester
   in-process, so there is a client to check), logout, authz. */
static Std_ReturnType ToServer(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* n, void*) {
    return Uds29Srv_HandleRequest(req, len, resp, n);
}

static int ServerMain(int argc, char** argv) {
    Uds29Srv_ConfigType c{};
    c.pki.mode = UDS29_PKI_SAMPLE;
    c.profile = &kExampleProfile;
    std::string root = std::string(UDS29_SAMPLE_DIR) + "/root_ca.pem";
    for (int i = 0; i < argc; i++) {
        if (!std::strcmp(argv[i], "--ca") && i + 1 < argc) { c.pki.mode = UDS29_PKI_USER; c.pki.root_ca_path = argv[++i]; root = c.pki.root_ca_path; }
        else if (!std::strcmp(argv[i], "--cert") && i + 1 < argc) { c.pki.mode = UDS29_PKI_USER; c.pki.cert_path = argv[++i]; }
        else if (!std::strcmp(argv[i], "--key") && i + 1 < argc) { c.pki.mode = UDS29_PKI_USER; c.pki.key_path = argv[++i]; }
    }
    if (Uds29Srv_Init(&c) != E_OK) { std::fputs("ERR cannot load ECU PKI\n", stderr); return 1; }
    Uds29Srv_SetAccessRules(kExampleRules, EX_NRULES);
    Uds29_ConfigType cc{0x00, 32};
    Uds29_Init(&cc);
    Uds29_SetTransport(ToServer, nullptr);
    std::string line;
    while (std::getline(std::cin, line)) {
        Uds29_Bytes b;
        if (line.empty() || line[0] == '#') continue;
        std::istringstream in(line);
        std::string cmd; in >> cmd;
        if (cmd == "login") {
            std::string crt, key; in >> crt >> key;
            Uds29_PkiConfigType p{}; p.mode = UDS29_PKI_USER; p.root_ca_path = root.c_str(); p.cert_path = crt.c_str(); p.key_path = key.c_str();
            bool ok = Uds29_SetPki(&p) == E_OK && Uds29_AuthenticateUnidirectional() == E_OK;
            std::puts(ok ? "LOGIN OK" : "LOGIN FAILED");
            continue;
        }
        if (cmd == "logout") { std::puts(Uds29_DeAuthenticate() == E_OK ? "LOGOUT OK" : "LOGOUT FAILED"); continue; }
        if (cmd == "authz") {
            Uds29_Authz a;
            if (Uds29Srv_GetAuthz(&a) != E_OK) { std::puts("not authenticated"); continue; }
            std::printf("roles=0x%08X services=%u dids=%u rids=%u\n", a.roles, a.n_services, a.n_dids, a.n_rids);
            continue;
        }
        if (cmd == "access") {
            std::string rest; std::getline(in, rest);
            if (!ParseHex(rest, b) || b.size() > UDS29_MAX_MSG_LEN) { std::puts("ERR bad hex"); continue; }
            uint8_t nrc = 0;
            if (Uds29Srv_CheckAccess(b.data(), (uint16_t)b.size(), &nrc) == E_OK) std::puts("ALLOWED");
            else std::printf("DENIED %02X %02X %02X\n", 0x7F, b[0], nrc);
            continue;
        }
        if (!ParseHex(line, b) || b.size() > UDS29_MAX_MSG_LEN) { std::puts("ERR bad hex"); continue; }
        uint8_t rx[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof rx;
        if (Uds29Srv_HandleRequest(b.data(), (uint16_t)b.size(), rx, &n) != E_OK) { std::puts("ERR no response"); continue; }
        std::puts(Hex(rx, n).c_str());
    }
    Uds29_DeInit();
    Uds29Srv_DeInit();
    return 0;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--role") && i + 1 < argc) {
            const char* r = argv[i + 1];
            if (!std::strcmp(r, "server")) return ServerMain(argc - 1, argv + 1);
            if (std::strcmp(r, "client")) { std::fputs("usage: uds29_cli [--role client|server [--ca F --cert F --key F]]\n", stderr); return 2; }
        }
    }
    Uds29SimEcu ecu;
    Uds29_ConfigType cfg{0x00, 32};
    Uds29_Init(&cfg);
    Uds29_SetTransport(Uds29SimEcu::Transport, &ecu);
    Uds29_SetEventCallback(OnEvent);
    bool pki_ok = false;
    std::string fault = "none";
#ifdef UDS29_WITH_IDSM
    IdsM_MonitorConfigType mon{};
    Uds29_IdsM_ConfigType icfg;
    Uds29_IdsM_GetDefaultConfig(&icfg);
    mon.monitor_id = icfg.monitor_id; mon.event_buffer_size = 64; mon.severity_threshold = IDSM_SEVERITY_LOW;
    mon.enabled_in_run = true;
    IdsM_Init(&mon, 1);
    IdsM_SetOperatingMode(IDSM_RUN_MODE);
    IdsM_SetDemReportCallback(OnDem);
    Uds29_IdsM_Init(&icfg);
    Uds29_SetEventCallback(OnEvent); /* prints, then chains into the bridge */
#endif
    std::puts("=== UDS 0x29 Authentication Simulator (type 'help') ===");

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string cmd; in >> cmd;
        if (cmd.empty() || cmd[0] == '#') continue;
        std::string a; in >> a;
        std::string rest; std::getline(in, rest);

        if (cmd == "quit") break;
        else if (cmd == "help") Help();
        else if (cmd == "pki") {
            LoadedPki np;
            if (a == "sample") np.cfg.mode = UDS29_PKI_SAMPLE;
            else if (a == "load") {
                std::istringstream r(rest);
                std::string tok, fmt;
                bool ok = (r >> np.ca >> np.cert >> np.key) ? true : false;
                while (ok && (r >> tok)) {
                    if (tok == "der") fmt = tok;
                    else if (tok == "--inter" || tok == "--crl") {
                        std::string f;
                        std::vector<std::string>& v = tok == "--inter" ? np.inter : np.crl;
                        ok = (r >> f) && v.size() < (tok == "--inter" ? UDS29_MAX_INTERMEDIATES : UDS29_MAX_CRLS);
                        if (ok) v.push_back(f);
                    } else ok = false;
                }
                if (!ok) { std::puts("[ERR] pki load <ca> <cert> <key> [der] [--inter f]... [--crl f]... (max UDS29_MAX_INTERMEDIATES / UDS29_MAX_CRLS)"); continue; }
                np.cfg.mode = UDS29_PKI_USER; np.cfg.format = fmt == "der" ? UDS29_PKI_FORMAT_DER : UDS29_PKI_FORMAT_PEM;
            } else { std::puts("[ERR] pki sample | pki load <ca> <cert> <key> [der] [--inter f]... [--crl f]..."); continue; }
            g_pki = np; g_pki.Bind(); g_pki.set = true;
            /* ponytail: with `pki load` the sim ECU reuses the same cert/key as its identity */
            pki_ok = ecu.Init(g_pki.cfg) && Uds29_SetPki(&g_pki.cfg) == E_OK;
            std::puts(pki_ok ? "[PKI] loaded" : "[PKI ERR] load failed (bad files, key/cert mismatch or chain invalid)");
        }
        else if (cmd == "auth" && (a == "uni" || a == "bi")) {
            Std_ReturnType r = a == "bi" ? Uds29_AuthenticateBidirectional() : Uds29_AuthenticateUnidirectional();
            std::printf("[AUTH] %s -> %s (state %s)\n", a.c_str(), r == E_OK ? "OK" : "FAILED", kStates[Uds29_GetState()]);
        }
        else if (cmd == "deauth")
            std::printf("[AUTH] deauth -> %s (state %s)\n", Uds29_DeAuthenticate() == E_OK ? "OK" : "FAILED", kStates[Uds29_GetState()]);
        else if (cmd == "send" || cmd == "decode") {
            Uds29_Bytes b;
            if (!ParseHex(a + rest, b)) { std::puts("[ERR] bad hex"); continue; }
            if (cmd == "decode") { Decode(b); continue; }
            if (b.size() > UDS29_MAX_MSG_LEN) { std::puts("[ERR] message longer than UDS29_MAX_MSG_LEN"); continue; }
            uint8_t rx[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof rx;
            Std_ReturnType r = Uds29_SendRaw(b.data(), (uint16_t)b.size(), rx, &n);
            if (r != E_OK) { std::printf("[SEND] failed (0x%02X)\n", r); continue; }
            std::printf("RX: %s\n", Hex(rx, n).c_str());
            Decode(Uds29_Bytes(rx, rx + n));
        }
        else if (cmd == "inject") {
            Uds29_SimFault f; uint8_t nrc = 0;
            if (a == "none") f = UDS29_SIM_FAULT_NONE;
            else if (a == "expired") f = UDS29_SIM_FAULT_EXPIRED_CERT;
            else if (a == "badsig") f = UDS29_SIM_FAULT_BAD_SIGNATURE;
            else if (a == "mismatch") f = UDS29_SIM_FAULT_CHALLENGE_MISMATCH;
            else if (a == "wrongfmt") f = UDS29_SIM_FAULT_WRONG_CERT_FORMAT;
            else if (a == "nrc") {
                Uds29_Bytes b;
                if (!ParseHex(rest, b) || b.size() != 1) { std::puts("[ERR] inject nrc <hex byte>"); continue; }
                f = UDS29_SIM_FAULT_FORCE_NRC; nrc = b[0];
            } else { std::puts("[ERR] inject <none|expired|badsig|mismatch|wrongfmt|nrc <hex>>"); continue; }
            ecu.SetFault(f, nrc);
            fault = a == "nrc" ? "nrc" + rest : a;
            std::printf("[SIM] fault = %s\n", fault.c_str());
        }
        else if (cmd == "status")
            std::printf("[STATUS] state=%s pki=%s fault=%s log=%u\n", kStates[Uds29_GetState()],
                        pki_ok ? "loaded" : "not loaded", fault.c_str(), Uds29_GetLogCount());
        else if (cmd == "log") {
            for (uint32_t i = 0; i < Uds29_GetLogCount(); i++) {
                Uds29_DirectionType d; uint8_t buf[UDS29_MAX_MSG_LEN]; uint16_t n;
                if (Uds29_GetLogEntry(i, &d, buf, sizeof buf, &n) == E_OK)
                    std::printf("%3u %s %s\n", i, d == UDS29_DIR_TX ? "TX" : "RX", Hex(buf, n).c_str());
            }
        }
        else if (cmd == "clear") Uds29_ClearLog();
        else if (cmd == "cert") CertCommand(a, rest);
#ifdef UDS29_WITH_IDSM
        else if (cmd == "idsm" && a == "status")
            {
            std::this_thread::sleep_for(std::chrono::milliseconds(30)); /* IDSM worker is async */
            std::printf("[IDSM] monitor=0x%04X pending=%u forwarded=%u last_event=0x%04X last_severity=%d\n", icfg.monitor_id,
                        IdsM_GetPendingEventCount(icfg.monitor_id), g_dem.load(), g_last_id.load(), g_last_sev.load());
        }
#endif
        else std::puts("[ERR] unknown command (type 'help')");
    }
#ifdef UDS29_WITH_IDSM
    Uds29_IdsM_DeInit();
    IdsM_DeInit();
#endif
    Uds29_DeInit();
}
