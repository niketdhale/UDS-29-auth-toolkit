#include "Uds29_IdsM.h"
#include "Uds29.h"
#include "Uds29_Os.h"
#include "IdsM.h"
#include <string.h>

static Uds29_IdsM_ConfigType g_cfg;
static bool g_on;

void Uds29_IdsM_GetDefaultConfig(Uds29_IdsM_ConfigType* c) {
    if (!c) return;
    memset(c, 0, sizeof *c);
    c->monitor_id = 0x0290;
    c->include_payload = true;
    c->success = (Uds29_IdsM_MapEntry){0x29F0, IDSM_SEVERITY_LOW, false};
    c->failure_no_nrc = (Uds29_IdsM_MapEntry){0x2900, IDSM_SEVERITY_HIGH, true};
    for (int i = 0; i < 256; i++) c->nrc[i] = (Uds29_IdsM_MapEntry){(uint16_t)(0x2900 | i), IDSM_SEVERITY_HIGH, true};
    c->nrc[UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED].severity = IDSM_SEVERITY_CRITICAL;
}

void Uds29_IdsM_OnEvent(const Uds29_EventType* e) {
    Uds29_IdsM_MapEntry m = {0, IDSM_SEVERITY_LOW, false};
    IdsM_MonitorIdType mon = 0;
    bool payload = false;
    Uds29_Os_Lock();
    bool on = g_on;
    if (on) {
        mon = g_cfg.monitor_id; payload = g_cfg.include_payload;
        if (e->kind == UDS29_EVT_FAILURE) m = e->nrc ? g_cfg.nrc[e->nrc] : g_cfg.failure_no_nrc;
        else m = g_cfg.success;
    }
    Uds29_Os_Unlock();
    if (!on || !(e->kind == UDS29_EVT_FAILURE || e->state == UDS29_STATE_AUTHENTICATED) || !m.enabled) return;

    uint8_t pl[3] = {e->nrc, e->sub_function, (uint8_t)e->state};
    IdsM_EventReportType r;
    memset(&r, 0, sizeof r);
    r.monitor_id = mon;
    r.event_id = m.event_id;
    r.severity = m.severity;
    r.timestamp_ms = Uds29_Os_GetTimeMs();
    if (payload) { r.payload = pl; r.payload_len = sizeof pl; }
    IdsM_ReportEvent(&r); /* result ignored: IDSM may be in a mode where the monitor is off */
}

Std_ReturnType Uds29_IdsM_Init(const Uds29_IdsM_ConfigType* cfg) {
    if (!cfg) return E_PARAM_POINTER;
    Uds29_Os_Lock(); g_cfg = *cfg; g_on = true; Uds29_Os_Unlock();
    Uds29_SetEventCallback(Uds29_IdsM_OnEvent);
    return E_OK;
}

Std_ReturnType Uds29_IdsM_DeInit(void) {
    Uds29_SetEventCallback(NULL);
    Uds29_Os_Lock(); g_on = false; Uds29_Os_Unlock();
    return E_OK;
}
