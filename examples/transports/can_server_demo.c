/* Two-process demo, ECU side: Uds29Srv_HandleRequest behind ISO-TP on a SocketCAN interface (Linux).
   Usage: can_server_demo [--if vcan0] [--tx 0x7E8] [--rx 0x7E0] [--pki sample | --ca F --cert F --key F]
   (the ECU receives on 0x7E0 and answers on 0x7E8). Runs until killed. */
#include "isotp.h"
#include "can_socketcan.h"
#include "demo_common.h"
#include <stdlib.h>

int main(int argc, char** argv) {
    const char* ifname = "vcan0";
    uint32_t tx = 0x7E8, rx = 0x7E0;
    Uds29Srv_ConfigType cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.pki.mode = UDS29_PKI_SAMPLE;
    cfg.challenge_len = 32;
    for (int i = 1; i < argc; i++) {
        int k = DemoPkiArg(argc, argv, &i, &cfg.pki);
        if (k == 2) { fprintf(stderr, "--pki: only 'sample'\n"); return 2; }
        if (k) continue;
        if (i + 1 < argc && !strcmp(argv[i], "--if")) ifname = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--tx")) tx = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--rx")) rx = (uint32_t)strtoul(argv[++i], NULL, 0);
        else { fprintf(stderr, "usage: %s [--if IF] [--tx ID] [--rx ID] [--pki sample | --ca F --cert F --key F]\n", argv[0]); return 2; }
    }
    if (Uds29Srv_Init(&cfg) != E_OK) { fprintf(stderr, "FAIL: cannot load ECU PKI\n"); return 1; }
    Uds29Srv_SetEventCallback(DemoServerEvent);
    SocketCan can;
    if (SocketCan_Open(&can, ifname, rx)) return 1;
    IsoTp_CanDriver drv = SocketCan_Driver(&can);
    IsoTp tp;
    IsoTp_Init(&tp, &drv, tx, rx);
    printf("[server] ISO-TP on %s: receive 0x%03X, answer 0x%03X\n", ifname, rx, tx);
    fflush(stdout);
    for (;;) {
        uint8_t req[UDS29_MAX_MSG_LEN], resp[UDS29_MAX_MSG_LEN];
        uint16_t n, rn = sizeof resp;
        int r = IsoTp_Recv(&tp, req, sizeof req, &n, 100);   /* wakes every 100 ms for the auth timeout */
        Uds29Srv_MainFunction();
        if (r != ISOTP_OK) continue;
        if (Uds29Srv_HandleRequest(req, n, resp, &rn) == E_OK && IsoTp_Send(&tp, resp, rn) != ISOTP_OK)
            puts("[server] ISO-TP send failed");
        fflush(stdout);
    }
}
