#pragma once
#include "Uds29_Types.h"
#include "Uds29_Transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C-compatible wrapper functions that bridge to C++ Uds29_Manager */
Std_ReturnType Uds29_Core_Init(const Uds29_ConfigType* config);
Std_ReturnType Uds29_Core_DeInit(void);
Std_ReturnType Uds29_Core_SetTransport(Uds29_TransportFn fn, void* ctx);
Std_ReturnType Uds29_Core_SetPki(const Uds29_PkiConfigType* pki);
void           Uds29_Core_SetEventCallback(Uds29_EventCallback cb);
Std_ReturnType Uds29_Core_Authenticate(bool bidirectional);
Std_ReturnType Uds29_Core_DeAuthenticate(void);
Uds29_StateType Uds29_Core_GetState(void);
Std_ReturnType Uds29_Core_SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len);
uint32_t       Uds29_Core_GetLogCount(void);
Std_ReturnType Uds29_Core_GetLogEntry(uint32_t index, Uds29_DirectionType* dir,
                                      uint8_t* buf, uint16_t cap, uint16_t* len);
void           Uds29_Core_ClearLog(void);

#ifdef __cplusplus
}
#endif
