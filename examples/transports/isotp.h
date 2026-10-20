#pragma once
/* Small userspace ISO-TP (ISO 15765-2) for classic CAN (8 byte frames): SF / FF / CF / FC, payload up to 4095.
   Blocking, single channel, no heap. Talks to any CAN frame driver (SocketCAN, loopback, your own).
   Not the kernel's can-isotp: see docs/transports.md. */
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* send: 0 = ok, <0 = error. recv: 1 = frame received, 0 = timeout, <0 = error. A driver may deliver frames of other
   ids; IsoTp ignores them. data holds 8 bytes at least. */
typedef struct {
    int (*send)(uint32_t id, const uint8_t* data, uint8_t dlc, void* ctx);
    int (*recv)(uint32_t* id, uint8_t* data, uint8_t* dlc, uint32_t timeout_ms, void* ctx);
    void* ctx;
} IsoTp_CanDriver;

typedef struct {
    const IsoTp_CanDriver* drv;
    uint32_t tx_id, rx_id;
    int      padding;      /* -1 = send short frames unpadded, 0..255 = pad every frame to 8 bytes with this byte */
    uint8_t  rx_bs;        /* our FlowControl when receiving: block size (0 = no more FC) ... */
    uint8_t  rx_stmin;     /* ... and STmin (0x00-0x7F ms, 0xF1-0xF9 = 100-900 us) */
    uint32_t n_bs_ms;      /* sender: wait for FlowControl */
    uint32_t n_cr_ms;      /* receiver: wait for the next consecutive frame */
} IsoTp;

typedef enum {
    ISOTP_OK = 0, ISOTP_TIMEOUT = -1, ISOTP_ERROR = -2, ISOTP_OVERFLOW = -3, ISOTP_BAD_SEQUENCE = -4, ISOTP_TOO_LONG = -5
} IsoTp_Result;

/* Defaults: padding 0xCC, rx_bs 0, rx_stmin 0, N_Bs = N_Cr = 1000 ms. */
void IsoTp_Init(IsoTp* t, const IsoTp_CanDriver* drv, uint32_t tx_id, uint32_t rx_id);
/* Sends one message (1..4095 bytes). */
int  IsoTp_Send(IsoTp* t, const uint8_t* data, uint16_t len);
/* Waits up to timeout_ms for the first frame of a message, then receives it. *len = bytes received. ISOTP_OVERFLOW
   (after sending FC overflow) if the message does not fit cap. */
int  IsoTp_Recv(IsoTp* t, uint8_t* buf, uint16_t cap, uint16_t* len, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
