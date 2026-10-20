#include "Uds29_SimEcu.h"
#include "Uds29_Server.h"
#include "Uds29_ServerTest.h"

bool Uds29SimEcu::Init(const Uds29_PkiConfigType& cfg) {
    Uds29Srv_ConfigType c{};
    c.pki = cfg;
    c.challenge_len = 32;
    inited_ = Uds29Srv_Init(&c) == E_OK;
    return inited_;
}

Uds29SimEcu::~Uds29SimEcu() { if (inited_) Uds29Srv_DeInit(); }

void Uds29SimEcu::SetFault(Uds29_SimFault f, uint8_t nrc) { Uds29Srv_SetFaultForTest(static_cast<Uds29Srv_Fault>(f), nrc); }

Std_ReturnType Uds29SimEcu::Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    if (!ctx) return E_PARAM_POINTER;
    return Uds29Srv_HandleRequest(req, len, resp, resp_len) == E_OK ? E_OK : E_NOT_OK;
}

#include "Uds29_SimEcu_C.h"
extern "C" {
void* Uds29_SimEcu_New(const Uds29_PkiConfigType* pki) {
    Uds29SimEcu* e = new Uds29SimEcu();
    if (!e->Init(*pki)) { delete e; return nullptr; }
    return e;
}
void Uds29_SimEcu_Free(void* ecu) { delete static_cast<Uds29SimEcu*>(ecu); }
Std_ReturnType Uds29_SimEcu_Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    return Uds29SimEcu::Transport(req, len, resp, resp_len, ctx);
}
}
