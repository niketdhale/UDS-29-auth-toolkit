/* Two-process demo, tester side: blocking Uds29 client API over a DoIP (ISO 13400-2) transport. Prints PASS / FAIL,
   exit code 0 on PASS. Usage: doip_client_demo [--host 127.0.0.1] [--port 13400] [--tester 0x0E80] [--ecu 0x1000]
                                                [--mode uni|bi] [--pki sample | --ca F --cert F --key F] */
#include "doip.h"
#include "demo_common.h"
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    const char* host = "127.0.0.1";
    int port = DOIP_PORT, bi = 0;
    Doip_Tester t = {-1, DOIP_ADDR_TESTER, DOIP_ADDR_ECU};
    Uds29_PkiConfigType pki = {UDS29_PKI_SAMPLE, NULL, NULL, NULL, UDS29_PKI_FORMAT_PEM};
    for (int i = 1; i < argc; i++) {
        int k = DemoPkiArg(argc, argv, &i, &pki);
        if (k == 2) { fprintf(stderr, "--pki: only 'sample'\n"); return 2; }
        if (k) continue;
        if (i + 1 < argc && !strcmp(argv[i], "--host")) host = argv[++i];
        else if (i + 1 < argc && !strcmp(argv[i], "--port")) port = atoi(argv[++i]);
        else if (i + 1 < argc && !strcmp(argv[i], "--tester")) t.tester = (uint16_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--ecu")) t.ecu = (uint16_t)strtoul(argv[++i], NULL, 0);
        else if (i + 1 < argc && !strcmp(argv[i], "--mode") && (!strcmp(argv[i + 1], "uni") || !strcmp(argv[i + 1], "bi"))) bi = !strcmp(argv[++i], "bi");
        else { fprintf(stderr, "usage: %s [--host IP] [--port N] [--tester 0xADDR] [--ecu 0xADDR] [--mode uni|bi] [--pki sample | --ca F --cert F --key F]\n", argv[0]); return 2; }
    }
    t.fd = Doip_Connect(host, port, t.tester);
    if (t.fd < 0) { puts("FAIL: connect / routing activation"); return 1; }
    printf("[client] DoIP routing activated (tester 0x%04X -> ECU 0x%04X)\n", t.tester, t.ecu);
    int rc = DemoRunClient(Doip_Transport, &t, &pki, bi);
    close(t.fd);
    return rc;
}
