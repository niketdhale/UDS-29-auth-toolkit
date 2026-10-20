#include "Uds29_IdsM.h"
#include "Uds29.h"
#include "IdsM.h"
#include <chrono>
#include <mutex>

static std::mutex g_mtx;
static Uds29_IdsM_ConfigType g_cfg;
static bool g_on = false;

void Uds29_IdsM_GetDefaultConfig(Uds29_IdsM_ConfigType* c) {
    if (!c) return;
    *c = Uds29_IdsM_ConfigType{};
    c->monitor_id = 0x0290;
    c->include_payload = true;
    c->success = {0x29F0, IDSM_SEVERITY_LOW, false};
    c->failure_no_nrc = {0x2900, IDSM_SEVERITY_HIGH, true};
    for (int i = 0; i < 256; i++) c->nrc[i] = {(uint16_t)(0x2900 | i), IDSM_SEVERITY_HIGH, true};
    c->nrc[UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED].severity = IDSM_SEVERITY_CRITICAL;
}

void Uds29_IdsM_OnEvent(const Uds29_EventType* e) {
    Uds29_IdsM_ConfigType c;
    { std::lock_guard<std::mutex> l(g_mtx); if (!g_on) return; c = g_cfg; }
    const Uds29_IdsM_MapEntry* m;
    if (e->kind == UDS29_EVT_FAILURE) m = e->nrc ? &c.nrc[e->nrc] : &c.failure_no_nrc;
    else if (e->state == UDS29_STATE_AUTHENTICATED) m = &c.success;
    else return;
    if (!m->enabled) return;

    uint8_t pl[3] = {e->nrc, e->sub_function, (uint8_t)e->state};
    IdsM_EventReportType r{};
    r.monitor_id = c.monitor_id;
    r.event_id = m->event_id;
    r.severity = m->severity;
    r.timestamp_ms = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (c.include_payload) { r.payload = pl; r.payload_len = sizeof pl; }
    IdsM_ReportEvent(&r); /* result ignored: IDSM may be in a mode where the monitor is off */
}

Std_ReturnType Uds29_IdsM_Init(const Uds29_IdsM_ConfigType* cfg) {
    if (!cfg) return E_PARAM_POINTER;
    { std::lock_guard<std::mutex> l(g_mtx); g_cfg = *cfg; g_on = true; }
    Uds29_SetEventCallback(Uds29_IdsM_OnEvent);
    return E_OK;
}

Std_ReturnType Uds29_IdsM_DeInit(void) {
    Uds29_SetEventCallback(nullptr);
    std::lock_guard<std::mutex> l(g_mtx);
    g_on = false;
    return E_OK;
}
