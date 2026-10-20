#include "Uds29.h"
#include "Uds29_SimEcu.h"
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
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

static void OnEvent(const Uds29_EventType* e) {
    if (e->kind == UDS29_EVT_STATE_CHANGE) std::printf("  [event] state -> %s\n", kStates[e->state]);
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
    std::puts("Commands: help, pki sample | pki load <ca> <cert> <key> [der],\n"
              "          auth uni|bi, deauth, send <hex>, decode <hex>,\n"
              "          inject <none|expired|badsig|mismatch|wrongfmt|nrc <hex>>,\n"
              "          status, log, clear"
#ifdef UDS29_WITH_IDSM
              ", idsm status"
#endif
              ", quit");
}

int main() {
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
            Uds29_PkiConfigType p{};
            std::string ca, crt, key, fmt;
            if (a == "sample") p.mode = UDS29_PKI_SAMPLE;
            else if (a == "load") {
                std::istringstream r(rest); r >> crt >> key >> fmt;
                ca = crt; crt = key; key = fmt; fmt.clear(); r >> fmt;
                p.mode = UDS29_PKI_USER; p.root_ca_path = ca.c_str(); p.cert_path = crt.c_str();
                p.key_path = key.c_str(); p.format = fmt == "der" ? UDS29_PKI_FORMAT_DER : UDS29_PKI_FORMAT_PEM;
            } else { std::puts("[ERR] pki sample | pki load <ca> <cert> <key> [der]"); continue; }
            /* ponytail: with `pki load` the sim ECU reuses the same cert/key as its identity */
            pki_ok = ecu.Init(p) && Uds29_SetPki(&p) == E_OK;
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
