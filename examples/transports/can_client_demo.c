/* Two-process demo, tester side: blocking Uds29 client API over ISO-TP on a SocketCAN interface (Linux).
   Prints PASS / FAIL, exit code 0 on PASS.
   Usage: can_client_demo [--if vcan0] [--tx 0x7E0] [--rx 0x7E8] [--mode uni|bi] [--pki sample | --ca F --cert F --key F] */
#include "isotp.h"
#include "can_socketcan.h"
#include "demo_common.h"
#include <stdlib.h>

/* Uds29_TransportFn: ctx = IsoTp*. Request, then the response; NRC 0x78 (response pending) waits for the real one. */
static Std_ReturnType IsoTpTransport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    IsoTp* t = ctx;
    uint16_t cap = *resp_len;
    if (IsoTp_Send(t, req, len) != ISOTP_OK) return E_NOT_OK;
    do {
        *resp_len = cap;
        if (IsoTp_Recv(t, resp, cap, resp_len, UDS29_P2_TIMEOUT_MS) != ISOTP_OK) return E_NOT_OK;
    } while (*resp_len == 3 && resp[0] == 0x7F && resp[2] == 0x78);
    return E_OK;
}

int main(int argc, char** argv) {
    const char* ifname = "vcan0";
    uint32_t tx = 0x7E0, rx = 0x7E8;
    int bi = 0;
    Uds29_PkiConfigType pki = {UDS29_PKI_SAMPLE, NULL, NULL, NULL, UDS29_PKI_FORMAT_PEM};
    for (int i = 1; i < argc; i++) {
        int k = DemoPkiArg(argc, argv, &i, &pki);
        if (k == 2) { fprintf(stderr, "--pki: only 'sample'\n"); return 2; }
        if (k) continue;
        if (i + 1 < argc && !strcmp(argv[i], "--if")) ifname = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--tx")) tx = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--rx")) rx = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--mode") && (!strcmp(argv[i + 1], "uni") || !strcmp(argv[i + 1], "bi"))) bi = !strcmp(argv[++i], "bi");
        else { fprintf(stderr, "usage: %s [--if IF] [--tx ID] [--rx ID] [--mode uni|bi] [--pki sample | --ca F --cert F --key F]\n", argv[0]); return 2; }
    }
    SocketCan can;
    if (SocketCan_Open(&can, ifname, rx)) { puts("FAIL: cannot open CAN interface"); return 1; }
    IsoTp_CanDriver drv = SocketCan_Driver(&can);
    IsoTp tp;
    IsoTp_Init(&tp, &drv, tx, rx);
    tp.n_bs_ms = tp.n_cr_ms = 1000;
    printf("[client] ISO-TP on %s: send 0x%03X, receive 0x%03X\n", ifname, tx, rx);
    int rc = DemoRunClient(IsoTpTransport, &tp, &pki, bi);
    SocketCan_Close(&can);
    return rc;
}
