/* OS port for Linux and QNX (POSIX threads, CLOCK_MONOTONIC). */
#define _POSIX_C_SOURCE 200809L
#include "Uds29_Os.h"
#include <pthread.h>
#include <time.h>

static pthread_mutex_t g_mtx;
static pthread_once_t  g_once = PTHREAD_ONCE_INIT;

static void MutexInit(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_mtx, &a);
    pthread_mutexattr_destroy(&a);
}

void Uds29_Os_Lock(void)   { pthread_once(&g_once, MutexInit); pthread_mutex_lock(&g_mtx); }
void Uds29_Os_Unlock(void) { pthread_mutex_unlock(&g_mtx); }

uint32_t Uds29_Os_GetTimeMs(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)((uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u);
}
