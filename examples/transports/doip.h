#pragma once
/* Minimal DoIP (ISO 13400-2:2019) over TCP: generic header, routing activation (0x0005 / 0x0006) and diagnostic
   message (0x8001) with positive / negative acknowledge (0x8002 / 0x8003). No vehicle announcement / discovery (UDP),
   no alive check, no TLS. Blocking POSIX sockets; used by the demos, not part of libuds29. */
#include "Uds29_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DOIP_PORT            13400
#define DOIP_VERSION         0x02
#define DOIP_ADDR_TESTER     0x0E80u  /* default logical addresses */
#define DOIP_ADDR_ECU        0x1000u
#define DOIP_MAX_PAYLOAD     1500u    /* >= UDS29_MAX_MSG_LEN + 4 */

enum {
    DOIP_GENERIC_NACK = 0x0000, DOIP_ROUTING_REQ = 0x0005, DOIP_ROUTING_RESP = 0x0006,
    DOIP_DIAG = 0x8001, DOIP_DIAG_ACK = 0x8002, DOIP_DIAG_NACK = 0x8003
};
/* generic header NACK codes / diagnostic NACK codes / routing activation response codes */
enum { DOIP_NACK_PATTERN = 0x00, DOIP_NACK_TYPE = 0x01, DOIP_NACK_TOO_LARGE = 0x02, DOIP_NACK_LENGTH = 0x04 };
enum { DOIP_DNACK_BAD_SA = 0x02, DOIP_DNACK_BAD_TA = 0x03 };
enum { DOIP_RA_UNKNOWN_SA = 0x00, DOIP_RA_SUCCESS = 0x10 };

/* Writes header + payload. 0 = ok, -1 = error. */
int Doip_Write(int fd, uint16_t type, const uint8_t* payload, uint32_t len);
/* Reads one message. 0 = ok, -1 = closed / error / timeout, -2 = bad header (version or inverse), -3 = payload > cap
   (the payload is then consumed and dropped). */
int Doip_Read(int fd, uint16_t* type, uint8_t* payload, uint32_t cap, uint32_t* len);

/* Tester side. Opens the TCP connection (receive timeout 5 s) and does the routing activation. -1 on failure. */
int Doip_Connect(const char* host, int port, uint16_t tester_addr);
/* Uds29_TransportFn: ctx = pointer to a Doip_Tester. Sends the request as diagnostic message, waits for the
   acknowledge and then for the diagnostic message carrying the response. */
typedef struct { int fd; uint16_t tester, ecu; } Doip_Tester;
Std_ReturnType Doip_Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx);

#ifdef __cplusplus
}
#endif
