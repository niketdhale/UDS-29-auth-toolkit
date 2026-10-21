#pragma once
#include "Uds29_Types.h"
#include "Uds29_Transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Non-blocking API: sends one request. req is valid only during the call; the callback may call
   Uds29_RxIndication() synchronously (loopback) but must not use req afterwards. Return E_OK if sent. */
typedef Std_ReturnType (*Uds29_TxCallback)(const uint8_t* req, uint16_t len, void* ctx);
typedef enum { UDS29_AUTH_UNIDIRECTIONAL = 0, UDS29_AUTH_BIDIRECTIONAL = 1 } Uds29_AuthDirectionType;

Std_ReturnType Uds29_Init(const Uds29_ConfigType* config);
Std_ReturnType Uds29_DeInit(void);
Std_ReturnType Uds29_SetTransport(Uds29_TransportFn fn, void* ctx);
/* Loads the client identity + trust anchor; E_NOT_OK if files are bad, key/cert mismatch or chain invalid. */
Std_ReturnType Uds29_SetPki(const Uds29_PkiConfigType* pki);
void           Uds29_SetEventCallback(Uds29_EventCallback cb);
/* Opt-in certificate validation for the ECU certificate (bidirectional); see Uds29_ConfigType.policy and
   docs/certificate-validation.md. Set the PKI (intermediates, CRLs) in Uds29_PkiConfigType.
   Time source for time_mode HOOK (and nothing else); NULL removes it. Call after Uds29_Init. */
Std_ReturnType Uds29_SetTimeSource(Uds29_TimeSourceFn fn, void* ctx);
/* Serial blacklist: an ECU certificate with one of these serials -> failure "revoked". list is not copied (must
   outlive its use); NULL / 0 removes it. */
Std_ReturnType Uds29_SetRevokedSerials(const Uds29_Serial* list, uint16_t count);

/* 0x01 + 0x03 */
Std_ReturnType Uds29_AuthenticateUnidirectional(void);
/* 0x02 + 0x03, also verifies the ECU certificate and its proof of ownership */
Std_ReturnType Uds29_AuthenticateBidirectional(void);
/* 0x00 */
Std_ReturnType Uds29_DeAuthenticate(void);
Uds29_StateType Uds29_GetState(void);

/* Non-blocking flow (same state machine as the calls above; blocking calls are refused while it runs):
   Start*() queues the first request (E_MODE_INVALID if not initialised/no PKI/no TX callback, E_NOT_OK if a flow is
   already running); Uds29_MainFunction() (call cyclically) sends each queued request via the TX callback and fails
   the session if no response arrives within UDS29_P2_TIMEOUT_MS; Uds29_RxIndication() delivers the response
   (E_NOT_OK if no request is pending or len > UDS29_MAX_MSG_LEN; otherwise E_OK, and NRCs/malformed
   data are reported through Uds29_GetState() and the event callback). Progress and result: Uds29_GetState(). */
Std_ReturnType Uds29_SetTxCallback(Uds29_TxCallback fn, void* ctx);
Std_ReturnType Uds29_StartAuthentication(Uds29_AuthDirectionType direction);
Std_ReturnType Uds29_StartDeAuthentication(void);
void           Uds29_MainFunction(void);
Std_ReturnType Uds29_RxIndication(const uint8_t* resp, uint16_t len);

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
