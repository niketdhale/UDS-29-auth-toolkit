#pragma once
#include "Uds29_Types.h"

/* Protocol-independent transport (CAN-TP, DoIP, loopback...).
   req/len: UDS request incl. SID. resp: caller buffer, *resp_len = capacity on
   entry, bytes written on return. Return E_OK if a response was received. */
typedef Std_ReturnType (*Uds29_TransportFn)(const uint8_t* req, uint16_t len,
                                            uint8_t* resp, uint16_t* resp_len, void* ctx);
