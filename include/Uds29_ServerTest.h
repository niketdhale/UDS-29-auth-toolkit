#pragma once
/* Test-only hooks of the server (fault injection, fake clock). Not installed, not for production. */
#include "Uds29_Types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UDS29SRV_FAULT_NONE = 0,
    UDS29SRV_FAULT_EXPIRED_CERT,        /* client cert judged at a time past its validity -> NRC 0x50 */
    UDS29SRV_FAULT_BAD_SIGNATURE,       /* 0x02: ECU corrupts its signature; 0x03: client POWN corrupted before the check -> 0x58 */
    UDS29SRV_FAULT_CHALLENGE_MISMATCH,  /* ECU signs/verifies against a different challenge */
    UDS29SRV_FAULT_WRONG_CERT_FORMAT,   /* 0x01: NRC 0x54; 0x02: ECU sends a garbage certificate */
    UDS29SRV_FAULT_FORCE_NRC            /* every well-formed request answered with `nrc` */
} Uds29Srv_Fault;

void Uds29Srv_SetFaultForTest(Uds29Srv_Fault fault, uint8_t nrc);
void Uds29Srv_SetClockForTest(uint32_t (*fn)(void)); /* NULL restores the OS clock */

#ifdef __cplusplus
}
#endif
