#include "can_loopback.h"
#include <errno.h>
#include <string.h>
#include <time.h>

void CanLoop_Init(CanLoop* b) {
    memset(b, 0, sizeof *b);
    for (int i = 0; i < 2; i++) {
        pthread_mutex_init(&b->q[i].m, NULL);
        pthread_cond_init(&b->q[i].c, NULL);
        b->end[i].bus = b; b->end[i].side = i;
    }
}

static void Deadline(struct timespec* ts, uint32_t ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000; ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

static int Send(uint32_t id, const uint8_t* data, uint8_t dlc, void* ctx) {
    CanLoopEnd* e = ctx;
    CanLoopQueue* q = &e->bus->q[1 - e->side];
    struct timespec dl;
    int rc = 0;
    if (dlc > 8) return -1;
    pthread_mutex_lock(&q->m);
    Deadline(&dl, 1000);
    while (q->n == CANLOOP_DEPTH && rc != ETIMEDOUT) rc = pthread_cond_timedwait(&q->c, &q->m, &dl); /* bus full: back-pressure */
    if (q->n < CANLOOP_DEPTH) {
        CanLoopFrame* f = &q->f[(q->head + q->n++) % CANLOOP_DEPTH];
        f->id = id; f->dlc = dlc; memcpy(f->data, data, dlc);
        rc = 0;
    } else rc = -1;
    pthread_cond_broadcast(&q->c);
    pthread_mutex_unlock(&q->m);
    return rc;
}

static int Recv(uint32_t* id, uint8_t* data, uint8_t* dlc, uint32_t timeout_ms, void* ctx) {
    CanLoopEnd* e = ctx;
    CanLoopQueue* q = &e->bus->q[e->side];
    struct timespec dl;
    int rc = 0;
    pthread_mutex_lock(&q->m);
    Deadline(&dl, timeout_ms);
    while (q->n == 0 && rc != ETIMEDOUT) rc = pthread_cond_timedwait(&q->c, &q->m, &dl);
    int got = 0;
    if (q->n) {
        CanLoopFrame* f = &q->f[q->head];
        *id = f->id; *dlc = f->dlc; memcpy(data, f->data, f->dlc);
        q->head = (q->head + 1) % CANLOOP_DEPTH; q->n--;
        got = 1;
    }
    pthread_cond_broadcast(&q->c);
    pthread_mutex_unlock(&q->m);
    return got;
}

IsoTp_CanDriver CanLoop_Driver(CanLoop* bus, int side) {
    IsoTp_CanDriver d = {Send, Recv, &bus->end[side]};
    return d;
}
