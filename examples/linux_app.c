/* Non-blocking API on Linux: the application thread calls Uds29_MainFunction() every 10 ms, a "bus" thread
   plays the transport (here: the simulated ECU) and delivers responses with Uds29_RxIndication(). Replace the
   bus thread with your SocketCAN / DoIP receive loop. */
#include "Uds29.h"
#include "Uds29_Cfg.h"
#include "Uds29_SimEcu_C.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;
static uint8_t  req_buf[UDS29_MAX_MSG_LEN];
static uint16_t req_len;
static int      quit;
static void*    ecu;

/* Called from Uds29_MainFunction() with the stack's lock held: only hand the frame over, never block. */
static Std_ReturnType TxCallback(const uint8_t* req, uint16_t len, void* ctx) {
    (void)ctx;
    pthread_mutex_lock(&m);
    memcpy(req_buf, req, len);
    req_len = len;
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&m);
    return E_OK;
}

static void* BusThread(void* arg) {
    (void)arg;
    pthread_mutex_lock(&m);
    while (!quit) {
        if (req_len == 0) { pthread_cond_wait(&cv, &m); continue; }
        uint8_t resp[UDS29_MAX_MSG_LEN];
        uint16_t n = sizeof resp, len = req_len;
        req_len = 0;
        pthread_mutex_unlock(&m);
        if (Uds29_SimEcu_Transport(req_buf, len, resp, &n, ecu) == E_OK) (void)Uds29_RxIndication(resp, n);
        pthread_mutex_lock(&m);
    }
    pthread_mutex_unlock(&m);
    return NULL;
}

/* Polls until the flow reaches `done` (or FAILED). */
static int Wait(Uds29_StateType done) {
    const struct timespec tick = {0, 10 * 1000000L};
    for (int i = 0; i < 1000; i++) { /* 10 s at most */
        Uds29_MainFunction();
        Uds29_StateType s = Uds29_GetState();
        if (s == done || s == UDS29_STATE_FAILED) return s;
        nanosleep(&tick, NULL);
    }
    return UDS29_STATE_FAILED;
}

int main(void) {
    Uds29_PkiConfigType pki = {UDS29_PKI_SAMPLE, NULL, NULL, NULL, UDS29_PKI_FORMAT_PEM};
    Uds29_ConfigType cfg = {0x00, 32};
    ecu = Uds29_SimEcu_New(&pki);
    if (!ecu || Uds29_Init(&cfg) != E_OK || Uds29_SetPki(&pki) != E_OK || Uds29_SetTxCallback(TxCallback, NULL) != E_OK) return 1;

    pthread_t bus;
    pthread_create(&bus, NULL, BusThread, NULL);

    int ok = Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL) == E_OK && Wait(UDS29_STATE_AUTHENTICATED) == UDS29_STATE_AUTHENTICATED;
    printf("authentication: %s\n", ok ? "AUTHENTICATED" : "FAILED");
    if (ok) {
        ok = Uds29_StartDeAuthentication() == E_OK && Wait(UDS29_STATE_IDLE) == UDS29_STATE_IDLE;
        printf("deauthentication: %s\n", ok ? "IDLE" : "FAILED");
    }

    pthread_mutex_lock(&m); quit = 1; pthread_cond_signal(&cv); pthread_mutex_unlock(&m);
    pthread_join(bus, NULL);
    Uds29_DeInit();
    Uds29_SimEcu_Free(ecu);
    return ok ? 0 : 1;
}
