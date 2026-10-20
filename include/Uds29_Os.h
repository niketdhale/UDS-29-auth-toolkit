#pragma once
/* OS port: implemented by src/os/Uds29_Os_Posix.c (Linux, QNX) or src/os/Uds29_Os_FreeRtos.c. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One global lock, RECURSIVE: event callbacks run with it held and may call back into the API.
   Not callable from an ISR. */
void     Uds29_Os_Lock(void);
void     Uds29_Os_Unlock(void);
/* Monotonic milliseconds (wraps after ~49 days). */
uint32_t Uds29_Os_GetTimeMs(void);

#ifdef __cplusplus
}
#endif
