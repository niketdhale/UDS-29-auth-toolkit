#pragma once
/* Host-only test double (STL allowed): not part of the embeddable core, built as the uds29_sim target. */
#include "Uds29_Transport.h"
#include "Uds29_Codec.h"
#include "Uds29_Crypto.h"
#include <vector>

typedef std::vector<uint8_t> Uds29_Bytes;

/* Values match Uds29Srv_Fault (Uds29_ServerTest.h). */
enum Uds29_SimFault {
    UDS29_SIM_FAULT_NONE = 0,
    UDS29_SIM_FAULT_EXPIRED_CERT,        /* ECU judges the client cert at a time past its validity -> NRC 0x50 */
    UDS29_SIM_FAULT_BAD_SIGNATURE,       /* ECU corrupts its signature (0x02) / the client's POWN is corrupted before checking (0x03 -> NRC 0x58) */
    UDS29_SIM_FAULT_CHALLENGE_MISMATCH,  /* ECU signs/verifies against a different challenge */
    UDS29_SIM_FAULT_WRONG_CERT_FORMAT,   /* 0x01: NRC 0x54; 0x02: ECU sends a garbage certificate */
    UDS29_SIM_FAULT_FORCE_NRC            /* every request answered with the NRC given to SetFault */
};

/* Thin C++ wrapper over the server module (Uds29Srv_*) with its test fault hooks. The server is a singleton:
   only one Uds29SimEcu may be initialised at a time. */
class Uds29SimEcu {
public:
    Uds29SimEcu() = default;
    ~Uds29SimEcu();
    Uds29SimEcu(const Uds29SimEcu&) = delete;
    Uds29SimEcu& operator=(const Uds29SimEcu&) = delete;

    bool Init(const Uds29_PkiConfigType& cfg);
    void SetFault(Uds29_SimFault f, uint8_t nrc = 0);

    /* Usable as Uds29_TransportFn with ctx = Uds29SimEcu*. */
    static Std_ReturnType Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx);

private:
    bool inited_ = false;
};
