/* In-process demo of certificate-based access control: tester and ECU in one process (blocking client API -> ECU
   handler). Four sample certificates (certs/sample/oem_profile.cnf) authenticate; every request is checked against
   the example rule table (access_example.h) and the allow-lists in the certificate. Exit code 0 if every outcome is
   the expected one. */
#include "Uds29.h"
#include "Uds29_Server.h"
#include "access_example.h"
#include <stdio.h>
#include <string.h>

/* The ECU's DCM, reduced to what matters: 0x29 goes to the authentication handler, anything else is access checked
   and, if allowed, answered with a stub positive response. */
static Std_ReturnType Ecu(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* n, void* ctx) {
    (void)ctx;
    uint8_t nrc;
    if (req[0] == UDS29_SID_REQUEST) return Uds29Srv_HandleRequest(req, len, resp, n);
    if (Uds29Srv_CheckAccess(req, len, &nrc) != E_OK) { resp[0] = 0x7F; resp[1] = req[0]; resp[2] = nrc; *n = 3; return E_OK; }
    resp[0] = (uint8_t)(req[0] + 0x40);
    memcpy(resp + 1, req + 1, len > 3 ? 2 : len - 1u);
    *n = len > 3 ? 3 : len;
    return E_OK;
}

static void Print(const uint8_t* p, uint16_t n) { for (uint16_t i = 0; i < n; i++) printf(i ? " %02X" : "%02X", p[i]); }

typedef struct { const char* what; const uint8_t* req; uint8_t n; bool allowed; } Case;
#define REQ(...) (const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__})

static int g_bad;

static void Run(const Case* c) {
    uint8_t resp[64];
    uint16_t rn = sizeof resp;
    Ecu(c->req, c->n, resp, &rn, NULL);
    bool allowed = resp[0] != 0x7F;
    printf("  %-25s ", c->what);
    Print(c->req, c->n);
    printf("\n  %25s -> ", "");
    Print(resp, rn);
    printf("   %s%s\n", allowed ? "allowed" : "denied", allowed == c->allowed ? "" : "   <-- UNEXPECTED");
    g_bad += allowed != c->allowed;
}

#define READ_VIN   "read VIN", REQ(0x22, 0xF1, 0x90)
#define READ_2     "read VIN + F18C", REQ(0x22, 0xF1, 0x90, 0xF1, 0x8C)
#define READ_F187  "read F187", REQ(0x22, 0xF1, 0x87)
#define WRITE_VIN  "write VIN", REQ(0x2E, 0xF1, 0x90, 0x41)
#define WRITE_F187 "write F187", REQ(0x2E, 0xF1, 0x87, 0x01)
#define FLASH      "request download (flash)", REQ(0x34, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00)
#define ROUTINE    "start routine FF00", REQ(0x31, 0x01, 0xFF, 0x00)
#define RESET      "ECU reset", REQ(0x11, 0x01)
#define READ_DTC   "read DTC (no rule)", REQ(0x19, 0x02, 0xFF)
#define TESTER_PRES "tester present", REQ(0x3E, 0x00)

static const Case kNone[] = {{READ_VIN, false}, {READ_DTC, true}, {TESTER_PRES, true}};
static const Case kWorkshop[] = {{READ_VIN, true}, {READ_2, true}, {WRITE_VIN, false}, {WRITE_F187, false}, {FLASH, false},
                                 {ROUTINE, false}, {RESET, false}, {READ_DTC, true}, {TESTER_PRES, true}};
static const Case kEngineering[] = {{READ_VIN, true}, {WRITE_VIN, true}, {WRITE_F187, false}, {FLASH, false}, {ROUTINE, true}, {RESET, true}};
static const Case kOem[] = {{READ_VIN, true}, {WRITE_VIN, true}, {WRITE_F187, true}, {FLASH, true}, {ROUTINE, true}, {RESET, true}, {READ_DTC, true}};
/* OEM role, but the certificate allows only services 22 / 3E and DIDs F190 / F18C */
static const Case kAllow[] = {{READ_VIN, true}, {READ_2, true}, {READ_F187, false}, {WRITE_VIN, false}, {FLASH, false}, {READ_DTC, false}, {TESTER_PRES, true}};

static void Tester(const char* name, const Case* cases, unsigned n) {
    char crt[256], key[256], root[256];
    snprintf(root, sizeof root, "%s/root_ca.pem", UDS29_SAMPLE_DIR);
    snprintf(crt, sizeof crt, "%s/tester_%s_cert.pem", UDS29_SAMPLE_DIR, name);
    snprintf(key, sizeof key, "%s/tester_%s_key.pem", UDS29_SAMPLE_DIR, name);
    Uds29_PkiConfigType pki = {UDS29_PKI_USER, root, crt, key, UDS29_PKI_FORMAT_PEM};
    Uds29_Authz az;
    printf("== tester_%s\n", name);
    if (Uds29_SetPki(&pki) != E_OK || Uds29_AuthenticateUnidirectional() != E_OK || Uds29Srv_GetAuthz(&az) != E_OK) {
        puts("  authentication FAILED");
        g_bad++;
        return;
    }
    printf("  authenticated: roles=0x%02X services=%u dids=%u rids=%u allow-list entries\n", az.roles, az.n_services, az.n_dids, az.n_rids);
    for (unsigned i = 0; i < n; i++) Run(&cases[i]);
    Uds29_DeAuthenticate();
}

int main(void) {
    Uds29Srv_ConfigType sc;
    memset(&sc, 0, sizeof sc);
    sc.pki.mode = UDS29_PKI_SAMPLE;
    sc.profile = &kExampleProfile;
    Uds29_ConfigType cc = {0x00, 32};
    if (Uds29Srv_Init(&sc) != E_OK || Uds29_Init(&cc) != E_OK || Uds29_SetTransport(Ecu, NULL) != E_OK) { puts("FAIL: init"); return 1; }
    Uds29Srv_SetAccessRules(kExampleRules, EX_NRULES);

    puts("== not authenticated");
    for (unsigned i = 0; i < sizeof kNone / sizeof *kNone; i++) Run(&kNone[i]);
    Tester("workshop", kWorkshop, sizeof kWorkshop / sizeof *kWorkshop);
    Tester("engineering", kEngineering, sizeof kEngineering / sizeof *kEngineering);
    Tester("oem", kOem, sizeof kOem / sizeof *kOem);
    Tester("allowlist", kAllow, sizeof kAllow / sizeof *kAllow);

    Uds29_DeInit();
    Uds29Srv_DeInit();
    puts(g_bad ? "FAIL" : "PASS");
    return g_bad ? 1 : 0;
}
