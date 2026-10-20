/* FreeRTOS integration sketch: one task drives the non-blocking API, a CAN ISR feeds responses.
   Needs the UDS29_OS=FREERTOS build of libuds29 plus a crypto backend (MBEDTLS or CUSTOM).
   Stubs (Can_Transmit, the ISR hook, the PKI file/ops setup) are placeholders for your CAN-TP driver. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "Uds29.h"
#include "Uds29_Cfg.h"

/* ── your CAN-TP driver (stubs) ── */
static Std_ReturnType Can_Transmit(const uint8_t* data, uint16_t len) { (void)data; (void)len; return E_OK; }

/* TX callback: runs inside Uds29_MainFunction() in the task, lock held; hand the frame to the driver and return. */
static Std_ReturnType TxCallback(const uint8_t* req, uint16_t len, void* ctx) {
    (void)ctx;
    return Can_Transmit(req, len);
}

/* Reassembled response from CAN-TP. Uds29_RxIndication() takes the stack's mutex, which is not ISR-safe:
   call it from a driver task / the TP rx task, not from the interrupt. The ISR only queues the frame. */
static QueueHandle_t g_rx_q;
typedef struct { uint16_t len; uint8_t data[UDS29_MAX_MSG_LEN]; } RxMsg;
static RxMsg g_rx_slot; /* single in-flight response (UDS is request/response) */

void Can_RxIsr_Stub(const uint8_t* data, uint16_t len) { /* called by your driver in ISR context */
    BaseType_t woken = pdFALSE;
    if (len <= UDS29_MAX_MSG_LEN) {
        g_rx_slot.len = len;
        for (uint16_t i = 0; i < len; i++) g_rx_slot.data[i] = data[i];
        uint8_t token = 1;
        xQueueSendFromISR(g_rx_q, &token, &woken);
    }
    portYIELD_FROM_ISR(woken);
}

static void AuthTask(void* arg) {
    (void)arg;
    uint8_t token;
    Uds29_ConfigType cfg = {0x00, 32};
    Uds29_PkiConfigType pki = {UDS29_PKI_USER, "ca.der", "tester.der", "tester.key", UDS29_PKI_FORMAT_DER}; /* or CUSTOM crypto ops */
    (void)Uds29_Init(&cfg);
    (void)Uds29_SetPki(&pki);
    (void)Uds29_SetTxCallback(TxCallback, NULL);
    (void)Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL);

    for (;;) {
        Uds29_MainFunction();                                    /* every 10 ms: send / time out */
        if (xQueueReceive(g_rx_q, &token, pdMS_TO_TICKS(10)) == pdTRUE)
            (void)Uds29_RxIndication(g_rx_slot.data, g_rx_slot.len);
        /* react to Uds29_GetState() == AUTHENTICATED / FAILED here */
    }
}

void Uds29_Example_Start(void) {
    g_rx_q = xQueueCreate(1, sizeof(uint8_t));
    xTaskCreate(AuthTask, "uds29", 2048, NULL, tskIDLE_PRIORITY + 2, NULL);
}
