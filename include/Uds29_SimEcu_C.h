#pragma once
/* C view of the host-only simulated ECU (linked from the uds29_sim target), for C examples. */
#include "Uds29_Types.h"
#ifdef __cplusplus
extern "C" {
#endif
void*          Uds29_SimEcu_New(const Uds29_PkiConfigType* pki); /* NULL on failure */
void           Uds29_SimEcu_Free(void* ecu);
/* Uds29_TransportFn-compatible: ctx = the pointer from Uds29_SimEcu_New */
Std_ReturnType Uds29_SimEcu_Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx);
#ifdef __cplusplus
}
#endif
