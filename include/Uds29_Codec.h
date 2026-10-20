#pragma once
#include "Uds29_Types.h"
#include <cstddef>
#include <vector>

typedef std::vector<uint8_t> Uds29_Bytes;

/* Union of all request fields; which ones are used depends on `sub`. */
struct Uds29_Req {
    uint8_t     sub = 0;
    uint8_t     comm = 0;                       /* communicationConfiguration */
    uint16_t    eval_id = 0;                    /* certificateEvaluationId */
    uint8_t     alg[UDS29_ALGORITHM_INDICATOR_LEN] = {};
    Uds29_Bytes cert, challenge, pown, eph, addl;
};

/* Union of all response fields. neg => 7F 29 nrc. */
struct Uds29_Resp {
    bool        neg = false;
    uint8_t     nrc = 0;
    uint8_t     sub = 0;
    uint8_t     ret = 0;                        /* authenticationReturnParameter */
    uint8_t     alg[UDS29_ALGORITHM_INDICATOR_LEN] = {};
    Uds29_Bytes cert, challenge, pown, eph, session_key, addl;
};

namespace Uds29Codec {
/* Encode returns empty on failure (bad sub-function, field > 65535 bytes). */
Uds29_Bytes EncodeRequest(const Uds29_Req& r);
Uds29_Bytes EncodeResponse(const Uds29_Resp& r);
/* Decode returns false on wrong SID, truncation, trailing bytes or bad sub-function. */
bool DecodeRequest(const uint8_t* d, size_t n, Uds29_Req& r);
bool DecodeResponse(const uint8_t* d, size_t n, Uds29_Resp& r);

const char* NrcToString(uint8_t nrc);
const char* ReturnParamToString(uint8_t ret);
}
