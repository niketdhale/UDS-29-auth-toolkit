#include "Uds29_IdsM.h"
#ifdef UDS29_WITH_CLIENT
#include "Uds29.h"
#endif
#ifdef UDS29_WITH_SERVER
#include "Uds29_Server.h"
#endif
#include "Uds29_Os.h"
#include "IdsM.h"
#include <string.h>

static Uds29_IdsM_ConfigType g_cfg;
static bool g_on, g_client, g_server;

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
    if (e->kind == UDS29_EVT_WARNING) return;
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

static Std_ReturnType Setup(const Uds29_IdsM_ConfigType* cfg, bool server) {
    if (!cfg) return E_PARAM_POINTER;
    Uds29_Os_Lock();
    g_cfg = *cfg; g_on = true;
    if (server) g_server = true; else g_client = true;
    Uds29_Os_Unlock();
    return E_OK;
}

#ifdef UDS29_WITH_CLIENT
Std_ReturnType Uds29_IdsM_Init(const Uds29_IdsM_ConfigType* cfg) {
    Std_ReturnType r = Setup(cfg, false);
    if (r == E_OK) Uds29_SetEventCallback(Uds29_IdsM_OnEvent);
    return r;
}
#endif

#ifdef UDS29_WITH_SERVER
Std_ReturnType Uds29_IdsM_InitServer(const Uds29_IdsM_ConfigType* cfg) {
    Std_ReturnType r = Setup(cfg, true);
    if (r == E_OK) Uds29Srv_SetEventCallback(Uds29_IdsM_OnEvent);
    return r;
}
#endif

Std_ReturnType Uds29_IdsM_DeInit(void) {
#ifdef UDS29_WITH_CLIENT
    if (g_client) Uds29_SetEventCallback(NULL);
#endif
#ifdef UDS29_WITH_SERVER
    if (g_server) Uds29Srv_SetEventCallback(NULL);
#endif
    Uds29_Os_Lock(); g_on = g_client = g_server = false; Uds29_Os_Unlock();
    return E_OK;
}
