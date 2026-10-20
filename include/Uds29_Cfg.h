#pragma once
/* Static buffer sizes of the core library. Override with -D (or the CMake cache variable of the same name);
   every translation unit that includes the headers must see the same values. */

#ifndef UDS29_MAX_CERT_LEN
#define UDS29_MAX_CERT_LEN 1024u      /* DER certificate (peer, own, and the field in a message) */
#endif
#ifndef UDS29_MAX_CHALLENGE_LEN
#define UDS29_MAX_CHALLENGE_LEN 64u   /* challenge; also the 'additional parameter' field */
#endif
#ifndef UDS29_MAX_SIG_LEN
#define UDS29_MAX_SIG_LEN 128u        /* signature; also the ephemeral public key and session key fields */
#endif
#ifndef UDS29_MAX_MSG_LEN
#define UDS29_MAX_MSG_LEN 1300u       /* largest request/response handled (also the size of one log entry) */
#endif
#ifndef UDS29_LOG_DEPTH
#define UDS29_LOG_DEPTH 32u           /* exchange log entries kept; the oldest is dropped when full */
#endif
#ifndef UDS29_P2_TIMEOUT_MS
#define UDS29_P2_TIMEOUT_MS 5000u     /* non-blocking API: max wait for each response before the session FAILS */
#endif

#if UDS29_MAX_MSG_LEN > 0xFFFFu
#error "UDS29_MAX_MSG_LEN must fit in uint16_t"
#endif
