#pragma once
/* Host-only test double (STL allowed): not part of the embeddable core, built as the uds29_sim target. */
#include "Uds29_Transport.h"
#include "Uds29_Codec.h"
#include "Uds29_Crypto.h"
#include <vector>

typedef std::vector<uint8_t> Uds29_Bytes;

enum Uds29_SimFault {
    UDS29_SIM_FAULT_NONE = 0,
    UDS29_SIM_FAULT_EXPIRED_CERT,        /* ECU judges the client cert at a time past its validity -> NRC 0x50 */
    UDS29_SIM_FAULT_BAD_SIGNATURE,       /* ECU corrupts its signature (0x02) / the client's POWN is corrupted before checking (0x03 -> NRC 0x58) */
    UDS29_SIM_FAULT_CHALLENGE_MISMATCH,  /* ECU signs/verifies against a different challenge */
    UDS29_SIM_FAULT_WRONG_CERT_FORMAT,   /* 0x01: NRC 0x54; 0x02: ECU sends a garbage certificate */
    UDS29_SIM_FAULT_FORCE_NRC            /* every request answered with the NRC given to SetFault */
};

/* Loopback server side of SID 0x29 (sub-functions 0x00-0x03 and 0x08). */
class Uds29SimEcu {
public:
    Uds29SimEcu() = default;
    ~Uds29SimEcu() { Uds29_Crypto_FreeIdentity(id_); }
    Uds29SimEcu(const Uds29SimEcu&) = delete;
    Uds29SimEcu& operator=(const Uds29SimEcu&) = delete;

    bool Init(const Uds29_PkiConfigType& cfg);
    void SetFault(Uds29_SimFault f, uint8_t nrc = 0) { fault_ = f; forced_nrc_ = nrc; }

    /* Usable as Uds29_TransportFn with ctx = Uds29SimEcu*. */
    static Std_ReturnType Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx);

private:
    Uds29_Bytes Handle(const uint8_t* req, size_t len);

    void* id_ = nullptr;
    uint8_t cert_[UDS29_MAX_CERT_LEN];
    uint16_t cert_len_ = 0;
    Uds29_SimFault fault_ = UDS29_SIM_FAULT_NONE;
    uint8_t forced_nrc_ = 0;
    bool cert_ok_ = false;
    Uds29_Bytes client_cert_, challenge_server_;
};
