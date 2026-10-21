#pragma once
/* Internal (not installed): peer-certificate verification pipeline and proof-of-ownership data, shared by client and server. */
#include "Uds29_Crypto.h"

typedef struct {
    Uds29_CertPolicy    policy;
    Uds29_TimeSourceFn  time_fn;
    void*               time_ctx;
    const Uds29_Serial* revoked;     /* not copied */
    uint16_t            n_revoked;
    int64_t             max_time;    /* latest trusted time seen (monotonic guard) */
} Uds29_Verifier;

/* Trusted time -> backend chain/CRL/validity check -> serial blacklist -> key usage / EKU / algorithm policy.
   at_override != 0 (test fault) replaces the time logic. *skipped is set when time_mode SKIP_WITH_EVENT left the dates unchecked. */
Uds29_PkiResult Uds29_Verifier_Check(Uds29_Verifier* v, void* ident, const uint8_t* der, uint16_t len,
                                     int64_t at_override, bool* skipped);

typedef struct {
    const uint8_t *server_ch, *client_ch, *own_cert, *peer_cert, *raw;
    uint16_t       server_len, client_len, own_len, peer_len, raw_len;
    uint8_t        comm;
    bool           bidi;
} Uds29_PownIn;

/* Signed data for a proof of ownership. False if an element is unavailable (no certificate, no SHA-256) or out does not fit. */
bool Uds29_Pown_Build(const Uds29_PownFormat* f, const Uds29_PownIn* in, uint8_t* out, uint16_t cap, uint16_t* n);
/* Worst case size of the above with UDS29_POWN_MAX_ELEMENTS elements (+1: test fault byte). */
#define UDS29_POWN_DATA_MAX (UDS29_POWN_MAX_ELEMENTS * (UDS29_MAX_CHALLENGE_LEN > 32u ? UDS29_MAX_CHALLENGE_LEN : 32u) + 1u)
