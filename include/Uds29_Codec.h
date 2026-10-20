#pragma once
#include "Uds29_Types.h"
#include "Uds29_Cfg.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Union of all request fields; which ones are used depends on `sub`. Variable fields are fixed buffers
   with an explicit length (<= the buffer size). */
typedef struct {
    uint8_t  sub;
    uint8_t  comm;                              /* communicationConfiguration */
    uint16_t eval_id;                           /* certificateEvaluationId */
    uint8_t  alg[UDS29_ALGORITHM_INDICATOR_LEN];
    uint16_t cert_len, challenge_len, pown_len, eph_len, addl_len;
    uint8_t  cert[UDS29_MAX_CERT_LEN];
    uint8_t  challenge[UDS29_MAX_CHALLENGE_LEN];
    uint8_t  pown[UDS29_MAX_SIG_LEN];
    uint8_t  eph[UDS29_MAX_SIG_LEN];
    uint8_t  addl[UDS29_MAX_CHALLENGE_LEN];
} Uds29_Req;

/* Union of all response fields. neg => 7F 29 nrc. */
typedef struct {
    bool     neg;
    uint8_t  nrc;
    uint8_t  sub;
    uint8_t  ret;                               /* authenticationReturnParameter */
    uint8_t  alg[UDS29_ALGORITHM_INDICATOR_LEN];
    uint16_t cert_len, challenge_len, pown_len, eph_len, session_key_len, addl_len;
    uint8_t  cert[UDS29_MAX_CERT_LEN];
    uint8_t  challenge[UDS29_MAX_CHALLENGE_LEN];
    uint8_t  pown[UDS29_MAX_SIG_LEN];
    uint8_t  eph[UDS29_MAX_SIG_LEN];
    uint8_t  session_key[UDS29_MAX_SIG_LEN];
    uint8_t  addl[UDS29_MAX_CHALLENGE_LEN];
} Uds29_Resp;

/* Encode return the message length, 0 on failure (bad sub-function, a field length above its buffer,
   or the message not fitting `cap`). */
uint16_t Uds29_Codec_EncodeRequest(const Uds29_Req* r, uint8_t* out, uint16_t cap);
uint16_t Uds29_Codec_EncodeResponse(const Uds29_Resp* r, uint8_t* out, uint16_t cap);
/* Decode returns false (and zeroes *r) on wrong SID, truncation, trailing bytes, bad sub-function
   or a field longer than its buffer. */
bool Uds29_Codec_DecodeRequest(const uint8_t* d, size_t n, Uds29_Req* r);
bool Uds29_Codec_DecodeResponse(const uint8_t* d, size_t n, Uds29_Resp* r);

const char* Uds29_Codec_NrcToString(uint8_t nrc);
const char* Uds29_Codec_ReturnParamToString(uint8_t ret);

#ifdef __cplusplus
}
#endif
