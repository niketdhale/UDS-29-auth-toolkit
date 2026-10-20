/* Two-process demo, ECU side: Uds29Srv_HandleRequest behind a DoIP (ISO 13400-2) TCP server. One tester at a time.
   Usage: doip_server_demo [--bind 127.0.0.1] [--port 13400] [--tester 0x0E80] [--ecu 0x1000]
                           [--pki sample | --ca F --cert F --key F] */
#include "doip.h"
#include "demo_common.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* One connection until it closes. Wakes every 100 ms for the authentication timeout. */
static void Serve(int c, uint16_t tester, uint16_t ecu) {
    int active = 0;
    for (;;) {
        struct pollfd p = {c, POLLIN, 0};
        int pr = poll(&p, 1, 100);
        Uds29Srv_MainFunction();
        if (pr == 0) continue;
        uint8_t in[DOIP_MAX_PAYLOAD], out[DOIP_MAX_PAYLOAD];
        uint16_t type;
        uint32_t n;
        int r = Doip_Read(c, &type, in, sizeof in, &n);
        if (r == -1) return;
        if (r == -2) { out[0] = DOIP_NACK_PATTERN; if (Doip_Write(c, DOIP_GENERIC_NACK, out, 1)) return; continue; }
        if (r == -3) { out[0] = DOIP_NACK_TOO_LARGE; if (Doip_Write(c, DOIP_GENERIC_NACK, out, 1)) return; continue; }
        if (type == DOIP_ROUTING_REQ && n >= 7) {
            uint16_t sa = (uint16_t)((in[0] << 8) | in[1]);
            active = sa == tester;
            printf("[server] routing activation from 0x%04X: %s\n", sa, active ? "accepted" : "denied");
            fflush(stdout);
            out[0] = in[0]; out[1] = in[1]; out[2] = (uint8_t)(ecu >> 8); out[3] = (uint8_t)ecu;
            out[4] = active ? DOIP_RA_SUCCESS : DOIP_RA_UNKNOWN_SA;
            memset(out + 5, 0, 4);
            if (Doip_Write(c, DOIP_ROUTING_RESP, out, 9)) return;
        } else if (type == DOIP_DIAG && n > 4) {
            uint16_t sa = (uint16_t)((in[0] << 8) | in[1]), ta = (uint16_t)((in[2] << 8) | in[3]);
            out[0] = (uint8_t)(ecu >> 8); out[1] = (uint8_t)ecu; out[2] = in[0]; out[3] = in[1];
            if (!active || sa != tester) { out[4] = DOIP_DNACK_BAD_SA; if (Doip_Write(c, DOIP_DIAG_NACK, out, 5)) return; continue; }
            if (ta != ecu)               { out[4] = DOIP_DNACK_BAD_TA; if (Doip_Write(c, DOIP_DIAG_NACK, out, 5)) return; continue; }
            out[4] = 0x00;                                                   /* positive acknowledge */
            if (Doip_Write(c, DOIP_DIAG_ACK, out, 5)) return;
            uint16_t rn = sizeof out - 4;
            if (Uds29Srv_HandleRequest(in + 4, (uint16_t)(n - 4), out + 4, &rn) != E_OK) return;
            if (Doip_Write(c, DOIP_DIAG, out, rn + 4u)) return;              /* out[0..3] = ecu -> tester */
        } else {
            out[0] = DOIP_NACK_TYPE;
            if (Doip_Write(c, DOIP_GENERIC_NACK, out, 1)) return;
        }
    }
}

int main(int argc, char** argv) {
    const char* bind_addr = "127.0.0.1";
    int port = DOIP_PORT;
    uint16_t tester = DOIP_ADDR_TESTER, ecu = DOIP_ADDR_ECU;
    Uds29Srv_ConfigType cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.pki.mode = UDS29_PKI_SAMPLE;
    cfg.challenge_len = 32;
    for (int i = 1; i < argc; i++) {
        int k = DemoPkiArg(argc, argv, &i, &cfg.pki);
        if (k == 2) { fprintf(stderr, "--pki: only 'sample'\n"); return 2; }
        if (k) continue;
        if (i + 1 < argc && !strcmp(argv[i], "--bind")) bind_addr = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--port")) port = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "--tester")) tester = (uint16_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--ecu")) ecu = (uint16_t)strtoul(argv[++i], NULL, 0);
        else { fprintf(stderr, "usage: %s [--bind IP] [--port N] [--tester 0xADDR] [--ecu 0xADDR] [--pki sample | --ca F --cert F --key F]\n", argv[0]); return 2; }
    }
    if (Uds29Srv_Init(&cfg) != E_OK) { fprintf(stderr, "FAIL: cannot load ECU PKI\n"); return 1; }
    Uds29Srv_SetEventCallback(DemoServerEvent);

    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &a.sin_addr) != 1 || bind(ls, (struct sockaddr*)&a, sizeof a) || listen(ls, 1)) {
        perror("FAIL: bind/listen");
        return 1;
    }
    printf("[server] DoIP ECU 0x%04X (tester 0x%04X) listening on %s:%d\n", ecu, tester, bind_addr, port);
    fflush(stdout);
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;
        puts("[server] tester connected");
        fflush(stdout);
        Serve(c, tester, ecu);
        close(c);
        puts("[server] tester disconnected");
        fflush(stdout);
    }
}
