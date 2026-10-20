#pragma once
/* In-process CAN bus with two endpoints (side 0 and 1) for tests: a frame sent by one side is received by the other. */
#include "isotp.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CANLOOP_DEPTH 64
typedef struct { uint32_t id; uint8_t data[8]; uint8_t dlc; } CanLoopFrame;
typedef struct {
    CanLoopFrame f[CANLOOP_DEPTH];
    unsigned head, n;
    pthread_mutex_t m;
    pthread_cond_t c;
} CanLoopQueue;
typedef struct CanLoop CanLoop;
typedef struct { CanLoop* bus; int side; } CanLoopEnd;
struct CanLoop { CanLoopQueue q[2]; CanLoopEnd end[2]; };

void CanLoop_Init(CanLoop* bus);
/* Driver for one side. The bus must outlive it. */
IsoTp_CanDriver CanLoop_Driver(CanLoop* bus, int side);

#ifdef __cplusplus
}
#endif
