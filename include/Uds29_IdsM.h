#pragma once
/* Optional bridge: Uds29 events -> IdsM_ReportEvent. Built only with UDS29_ENABLE_IDSM=ON. */
#include "Uds29_Types.h"
#include "IdsM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t               event_id;
    IdsM_EventSeverityType severity;
    bool                   enabled;
} Uds29_IdsM_MapEntry;

typedef struct {
    IdsM_MonitorIdType  monitor_id;     /* must be registered via IdsM_Init by the application */
    Uds29_IdsM_MapEntry success;        /* state change to AUTHENTICATED */
    Uds29_IdsM_MapEntry failure_no_nrc; /* failure detected by the client (nrc == 0) */
    Uds29_IdsM_MapEntry nrc[256];       /* failure with this NRC */
    bool                include_payload;/* payload = {nrc, sub_function, state} */
} Uds29_IdsM_ConfigType;

/* Defaults: monitor 0x0290; failures enabled, event_id = 0x2900 | nrc, HIGH;
   NRC 0x58 (ownership verification failed) CRITICAL; success 0x29F0 LOW, disabled; payload on. */
void           Uds29_IdsM_GetDefaultConfig(Uds29_IdsM_ConfigType* cfg);
/* Copies cfg and registers the bridge via Uds29_SetEventCallback (replaces any other callback). */
Std_ReturnType Uds29_IdsM_Init(const Uds29_IdsM_ConfigType* cfg);
Std_ReturnType Uds29_IdsM_DeInit(void);
/* The registered callback itself; call it from your own callback if you need to chain. */
void           Uds29_IdsM_OnEvent(const Uds29_EventType* event);

#ifdef __cplusplus
}
#endif
