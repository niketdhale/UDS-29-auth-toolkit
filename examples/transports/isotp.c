#include "isotp.h"
#include <string.h>
#include <time.h>

#define MAX_LEN 4095u
#define MAX_WAIT_FC 16u /* FlowControl WAIT frames tolerated per block */

static uint32_t NowMs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static void SleepUs(uint32_t us) {
    struct timespec ts = {(time_t)(us / 1000000u), (long)(us % 1000000u) * 1000L};
    nanosleep(&ts, NULL);
}

void IsoTp_Init(IsoTp* t, const IsoTp_CanDriver* drv, uint32_t tx_id, uint32_t rx_id) {
    memset(t, 0, sizeof *t);
    t->drv = drv; t->tx_id = tx_id; t->rx_id = rx_id;
    t->padding = 0xCC;
    t->n_bs_ms = t->n_cr_ms = 1000;
}

static int Tx(IsoTp* t, const uint8_t* d, uint8_t n) {
    uint8_t f[8];
    memcpy(f, d, n);
    if (t->padding >= 0) { memset(f + n, t->padding, 8u - n); n = 8; }
    return t->drv->send(t->tx_id, f, n, t->drv->ctx) == 0 ? ISOTP_OK : ISOTP_ERROR;
}

/* Next frame with our rx id within timeout_ms (frames of other ids are skipped). 0 = got one. */
static int Rx(IsoTp* t, uint8_t* f, uint8_t* n, uint32_t timeout_ms) {
    uint32_t t0 = NowMs();
    for (;;) {
        uint32_t el = NowMs() - t0, id;
        if (el > timeout_ms) return ISOTP_TIMEOUT;
        int r = t->drv->recv(&id, f, n, timeout_ms - el, t->drv->ctx);
        if (r < 0) return ISOTP_ERROR;
        if (r == 0) return ISOTP_TIMEOUT;
        if (id == t->rx_id && *n >= 1) return ISOTP_OK;
    }
}

static uint32_t StminUs(uint8_t s) {
    if (s <= 0x7F) return s * 1000u;
    if (s >= 0xF1 && s <= 0xF9) return (s - 0xF0u) * 100u;
    return 127000u; /* reserved values: the longest valid one */
}

/* Waits for a FlowControl CTS; returns its BS / STmin. */
static int WaitFc(IsoTp* t, uint8_t* bs, uint8_t* stmin) {
    for (unsigned w = 0; w <= MAX_WAIT_FC; w++) {
        uint8_t f[8], n;
        int r = Rx(t, f, &n, t->n_bs_ms);
        if (r) return r;
        if ((f[0] & 0xF0) != 0x30 || n < 3) continue;   /* not a FlowControl */
        switch (f[0] & 0x0F) {
        case 0: *bs = f[1]; *stmin = f[2]; return ISOTP_OK;
        case 1: continue;                                /* WAIT */
        case 2: return ISOTP_OVERFLOW;
        default: return ISOTP_ERROR;
        }
    }
    return ISOTP_TIMEOUT;
}

int IsoTp_Send(IsoTp* t, const uint8_t* data, uint16_t len) {
    if (len == 0 || len > MAX_LEN) return ISOTP_TOO_LONG;
    uint8_t f[8];
    if (len <= 7) {
        f[0] = (uint8_t)len;
        memcpy(f + 1, data, len);
        return Tx(t, f, (uint8_t)(len + 1));
    }
    f[0] = (uint8_t)(0x10 | (len >> 8)); f[1] = (uint8_t)len;
    memcpy(f + 2, data, 6);
    int r = Tx(t, f, 8);
    if (r) return r;
    uint16_t off = 6;
    uint8_t sn = 1, bs = 0, stmin = 0, left = 0;
    r = WaitFc(t, &bs, &stmin);
    if (r) return r;
    left = bs;
    while (off < len) {
        uint16_t n = (uint16_t)(len - off < 7 ? len - off : 7);
        f[0] = (uint8_t)(0x20 | sn);
        memcpy(f + 1, data + off, n);
        SleepUs(StminUs(stmin));
        r = Tx(t, f, (uint8_t)(n + 1));
        if (r) return r;
        off = (uint16_t)(off + n);
        sn = (sn + 1) & 0x0F;
        if (bs && off < len && --left == 0) {            /* block done: next FlowControl */
            r = WaitFc(t, &bs, &stmin);
            if (r) return r;
            left = bs;
        }
    }
    return ISOTP_OK;
}

static int SendFc(IsoTp* t, uint8_t fs, uint8_t bs, uint8_t stmin) {
    uint8_t f[3] = {(uint8_t)(0x30 | fs), bs, stmin};
    return Tx(t, f, 3);
}

int IsoTp_Recv(IsoTp* t, uint8_t* buf, uint16_t cap, uint16_t* len, uint32_t timeout_ms) {
    uint8_t f[8], n;
    *len = 0;
    for (;;) {                                           /* first frame: skip stray CF / FC */
        int r = Rx(t, f, &n, timeout_ms);
        if (r) return r;
        uint8_t type = f[0] >> 4;
        if (type == 0) {                                 /* SF */
            uint8_t l = f[0] & 0x0F;
            if (l == 0 || l > 7 || l > n - 1) return ISOTP_ERROR;
            if (l > cap) return ISOTP_OVERFLOW;
            memcpy(buf, f + 1, l);
            *len = l;
            return ISOTP_OK;
        }
        if (type == 1) break;                            /* FF */
    }
    uint16_t total = (uint16_t)(((f[0] & 0x0F) << 8) | f[1]);
    if (n != 8 || total < 8) return ISOTP_ERROR;
    if (total > cap) { SendFc(t, 2, 0, 0); return ISOTP_OVERFLOW; }
    memcpy(buf, f + 2, 6);
    uint16_t off = 6;
    uint8_t sn = 1, left = t->rx_bs;
    int r = SendFc(t, 0, t->rx_bs, t->rx_stmin);
    if (r) return r;
    while (off < total) {
        r = Rx(t, f, &n, t->n_cr_ms);
        if (r) return r;
        if ((f[0] >> 4) != 2) return ISOTP_ERROR;        /* anything but a CF aborts */
        if ((f[0] & 0x0F) != sn) return ISOTP_BAD_SEQUENCE;
        uint16_t c = (uint16_t)(total - off < 7 ? total - off : 7);
        if (n < c + 1u) return ISOTP_ERROR;
        memcpy(buf + off, f + 1, c);
        off = (uint16_t)(off + c);
        sn = (sn + 1) & 0x0F;
        if (t->rx_bs && off < total && --left == 0) {
            r = SendFc(t, 0, t->rx_bs, t->rx_stmin);
            if (r) return r;
            left = t->rx_bs;
        }
    }
    *len = total;
    return ISOTP_OK;
}
