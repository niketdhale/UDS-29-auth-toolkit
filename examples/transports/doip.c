#include "doip.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int ReadN(int fd, uint8_t* p, size_t n) {
    while (n) { ssize_t r = read(fd, p, n); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}
static int WriteN(int fd, const uint8_t* p, size_t n) {
    while (n) { ssize_t r = write(fd, p, n); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}

int Doip_Write(int fd, uint16_t type, const uint8_t* payload, uint32_t len) {
    uint8_t h[8] = {DOIP_VERSION, (uint8_t)~DOIP_VERSION, (uint8_t)(type >> 8), (uint8_t)type,
                    (uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len};
    return (WriteN(fd, h, 8) || WriteN(fd, payload, len)) ? -1 : 0;
}

int Doip_Read(int fd, uint16_t* type, uint8_t* payload, uint32_t cap, uint32_t* len) {
    uint8_t h[8];
    if (ReadN(fd, h, 8)) return -1;
    if (h[0] != DOIP_VERSION || h[1] != (uint8_t)~DOIP_VERSION) return -2;
    *type = (uint16_t)((h[2] << 8) | h[3]);
    *len = ((uint32_t)h[4] << 24) | ((uint32_t)h[5] << 16) | ((uint32_t)h[6] << 8) | h[7];
    if (*len > cap) {
        for (uint32_t i = 0; i < *len; i++) { uint8_t b; if (ReadN(fd, &b, 1)) return -1; }
        return -3;
    }
    return ReadN(fd, payload, *len) ? -1 : 0;
}

int Doip_Connect(const char* host, int port, uint16_t tester_addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {5, 0};
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 || connect(fd, (struct sockaddr*)&a, sizeof a)) { close(fd); return -1; }
    /* routing activation request: source address, activation type 0x00 (default), reserved (4) */
    uint8_t req[7] = {(uint8_t)(tester_addr >> 8), (uint8_t)tester_addr, 0, 0, 0, 0, 0}, rsp[64];
    uint16_t type;
    uint32_t n;
    if (Doip_Write(fd, DOIP_ROUTING_REQ, req, sizeof req) || Doip_Read(fd, &type, rsp, sizeof rsp, &n) ||
        type != DOIP_ROUTING_RESP || n < 5 || rsp[4] != DOIP_RA_SUCCESS) { close(fd); return -1; }
    return fd;
}

Std_ReturnType Doip_Transport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    Doip_Tester* t = ctx;
    uint8_t buf[DOIP_MAX_PAYLOAD];
    if (len + 4u > sizeof buf) return E_NOT_OK;
    buf[0] = (uint8_t)(t->tester >> 8); buf[1] = (uint8_t)t->tester; buf[2] = (uint8_t)(t->ecu >> 8); buf[3] = (uint8_t)t->ecu;
    memcpy(buf + 4, req, len);
    if (Doip_Write(t->fd, DOIP_DIAG, buf, len + 4u)) return E_NOT_OK;
    for (int acked = 0;;) {                     /* ACK first, then the response (other types are skipped) */
        uint16_t type;
        uint32_t n;
        if (Doip_Read(t->fd, &type, buf, sizeof buf, &n)) return E_NOT_OK;
        if (type == DOIP_DIAG_ACK) acked = 1;
        else if (type == DOIP_DIAG_NACK || type == DOIP_GENERIC_NACK) return E_NOT_OK;
        else if (type == DOIP_DIAG && acked && n > 4) {
            if (n - 4 > *resp_len) return E_NOT_OK;
            memcpy(resp, buf + 4, n - 4);
            *resp_len = (uint16_t)(n - 4);
            return E_OK;
        }
    }
}
