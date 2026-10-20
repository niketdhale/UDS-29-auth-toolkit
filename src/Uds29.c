#include "Uds29.h"
#include "Uds29_Manager_Wrapper.h"

Std_ReturnType Uds29_Init(const Uds29_ConfigType* config) {
    if (!config) return E_PARAM_POINTER;
    return Uds29_Core_Init(config);
}
Std_ReturnType Uds29_DeInit(void) { return Uds29_Core_DeInit(); }
Std_ReturnType Uds29_SetTransport(Uds29_TransportFn fn, void* ctx) {
    if (!fn) return E_PARAM_POINTER;
    return Uds29_Core_SetTransport(fn, ctx);
}
Std_ReturnType Uds29_SetPki(const Uds29_PkiConfigType* pki) {
    if (!pki) return E_PARAM_POINTER;
    return Uds29_Core_SetPki(pki);
}
void Uds29_SetEventCallback(Uds29_EventCallback cb) { Uds29_Core_SetEventCallback(cb); }
Std_ReturnType Uds29_AuthenticateUnidirectional(void) { return Uds29_Core_Authenticate(false); }
Std_ReturnType Uds29_AuthenticateBidirectional(void)  { return Uds29_Core_Authenticate(true); }
Std_ReturnType Uds29_DeAuthenticate(void) { return Uds29_Core_DeAuthenticate(); }
Uds29_StateType Uds29_GetState(void) { return Uds29_Core_GetState(); }
Std_ReturnType Uds29_SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len) {
    if (!req || !resp || !resp_len) return E_PARAM_POINTER;
    return Uds29_Core_SendRaw(req, len, resp, resp_len);
}
uint32_t Uds29_GetLogCount(void) { return Uds29_Core_GetLogCount(); }
Std_ReturnType Uds29_GetLogEntry(uint32_t index, Uds29_DirectionType* dir,
                                 uint8_t* buf, uint16_t cap, uint16_t* len) {
    if (!dir || !buf || !len) return E_PARAM_POINTER;
    return Uds29_Core_GetLogEntry(index, dir, buf, cap, len);
}
void Uds29_ClearLog(void) { Uds29_Core_ClearLog(); }
Std_ReturnType Uds29_SetTxCallback(Uds29_TxCallback fn, void* ctx) { return Uds29_Core_SetTxCallback(fn, ctx); }
Std_ReturnType Uds29_StartAuthentication(Uds29_AuthDirectionType d) {
    if (d != UDS29_AUTH_UNIDIRECTIONAL && d != UDS29_AUTH_BIDIRECTIONAL) return E_NOT_OK;
    return Uds29_Core_Start((int)d);
}
Std_ReturnType Uds29_StartDeAuthentication(void) { return Uds29_Core_Start(2); }
void Uds29_MainFunction(void) { Uds29_Core_MainFunction(); }
Std_ReturnType Uds29_RxIndication(const uint8_t* resp, uint16_t len) {
    if (!resp) return E_PARAM_POINTER;
    return Uds29_Core_RxIndication(resp, len);
}
