#pragma once
/* Shared by the four two-process demos (doip_*, can_*): PKI command line options, event printing, client flow. */
#include "Uds29.h"
#include "Uds29_Server.h"
#include <stdio.h>
#include <string.h>

static const char* const kDemoState[] = {"IDLE", "CERT_SENT", "CHALLENGE_RECEIVED", "POWN_SENT", "AUTHENTICATED", "FAILED"};

/* Consumes --pki sample | --ca F | --cert F | --key F at argv[*i]; returns 1 if it did, 2 on a bad value, else 0. */
static inline int DemoPkiArg(int argc, char** argv, int* i, Uds29_PkiConfigType* pki) {
    if (*i + 1 >= argc) return 0;
    if (!strcmp(argv[*i], "--pki")) { (*i)++; return strcmp(argv[*i], "sample") ? 2 : 1; }
    if (!strcmp(argv[*i], "--ca"))   { pki->mode = UDS29_PKI_USER; pki->root_ca_path = argv[++*i]; return 1; }
    if (!strcmp(argv[*i], "--cert")) { pki->mode = UDS29_PKI_USER; pki->cert_path = argv[++*i]; return 1; }
    if (!strcmp(argv[*i], "--key"))  { pki->mode = UDS29_PKI_USER; pki->key_path = argv[++*i]; return 1; }
    return 0;
}

static inline void DemoServerEvent(const Uds29_EventType* e) {
    if (e->kind == UDS29_EVT_STATE_CHANGE) printf("[server] state -> %s\n", kDemoState[e->state]);
    else printf("[server] NRC 0x%02X sub=0x%02X %s\n", e->nrc, e->sub_function, e->description);
    fflush(stdout);
}

static inline void DemoClientEvent(const Uds29_EventType* e) {
    if (e->kind == UDS29_EVT_FAILURE) printf("[client] failure sub=0x%02X nrc=0x%02X %s\n", e->sub_function, e->nrc, e->description);
}

/* Client side: init, authenticate (uni or bi), deauthenticate, print PASS / FAIL. Returns the exit code. */
static inline int DemoRunClient(Uds29_TransportFn tp, void* ctx, const Uds29_PkiConfigType* pki, int bi) {
    Uds29_ConfigType cfg = {0x00, 32};
    if (Uds29_Init(&cfg) != E_OK || Uds29_SetTransport(tp, ctx) != E_OK || Uds29_SetPki(pki) != E_OK) {
        puts("FAIL: client init / PKI");
        return 1;
    }
    Uds29_SetEventCallback(DemoClientEvent);
    int ok = (bi ? Uds29_AuthenticateBidirectional() : Uds29_AuthenticateUnidirectional()) == E_OK
             && Uds29_GetState() == UDS29_STATE_AUTHENTICATED;
    printf("[client] %s authentication: %s\n", bi ? "bidirectional" : "unidirectional", ok ? "AUTHENTICATED" : "FAILED");
    if (ok) {
        ok = Uds29_DeAuthenticate() == E_OK && Uds29_GetState() == UDS29_STATE_IDLE;
        printf("[client] deauthentication: %s\n", ok ? "OK" : "FAILED");
    }
    Uds29_DeInit();
    puts(ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
