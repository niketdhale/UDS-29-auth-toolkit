#pragma once
/* Linux raw SocketCAN driver for IsoTp (classic CAN). Needs a CAN interface (real or vcan) and AF_CAN in the kernel. */
#include "isotp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { int fd; } SocketCan;

/* Opens CAN_RAW on `ifname` with a receive filter on rx_id only. 0 = ok, -1 = error (errno set, message on stderr). */
int  SocketCan_Open(SocketCan* c, const char* ifname, uint32_t rx_id);
void SocketCan_Close(SocketCan* c);
IsoTp_CanDriver SocketCan_Driver(SocketCan* c);

#ifdef __cplusplus
}
#endif
