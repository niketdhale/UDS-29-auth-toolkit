#pragma once
#include "Uds29_Types.h"
#include "Uds29_Transport.h"

#ifdef __cplusplus
extern "C" {
#endif

Std_ReturnType Uds29_Init(const Uds29_ConfigType* config);
Std_ReturnType Uds29_DeInit(void);
Std_ReturnType Uds29_SetTransport(Uds29_TransportFn fn, void* ctx);
/* Loads the client identity + trust anchor; E_NOT_OK if files are bad, key/cert mismatch or chain invalid. */
Std_ReturnType Uds29_SetPki(const Uds29_PkiConfigType* pki);
void           Uds29_SetEventCallback(Uds29_EventCallback cb);

/* 0x01 + 0x03 */
Std_ReturnType Uds29_AuthenticateUnidirectional(void);
/* 0x02 + 0x03, also verifies the ECU certificate and its proof of ownership */
Std_ReturnType Uds29_AuthenticateBidirectional(void);
/* 0x00 */
Std_ReturnType Uds29_DeAuthenticate(void);
Uds29_StateType Uds29_GetState(void);

/* Sends bytes as-is and logs them; no state change. *resp_len = capacity in, length out. */
Std_ReturnType Uds29_SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len);

/* Exchange log */
uint32_t       Uds29_GetLogCount(void);
Std_ReturnType Uds29_GetLogEntry(uint32_t index, Uds29_DirectionType* dir,
                                 uint8_t* buf, uint16_t cap, uint16_t* len);
void           Uds29_ClearLog(void);

#ifdef __cplusplus
}
#endif
