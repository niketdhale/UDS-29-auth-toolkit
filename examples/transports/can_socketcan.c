#include "can_socketcan.h"
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int SocketCan_Open(SocketCan* c, const char* ifname, uint32_t rx_id) {
    c->fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (c->fd < 0) { perror("socket(PF_CAN)"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(c->fd, SIOCGIFINDEX, &ifr) < 0) { perror(ifname); close(c->fd); return -1; }
    struct sockaddr_can a;
    memset(&a, 0, sizeof a);
    a.can_family = AF_CAN; a.can_ifindex = ifr.ifr_ifindex;
    int ext = rx_id > CAN_SFF_MASK;
    struct can_filter flt = {ext ? (rx_id | CAN_EFF_FLAG) : rx_id, ext ? (CAN_EFF_MASK | CAN_EFF_FLAG) : (CAN_SFF_MASK | CAN_EFF_FLAG)};
    int off = 0; /* do not hear our own frames */
    if (setsockopt(c->fd, SOL_CAN_RAW, CAN_RAW_FILTER, &flt, sizeof flt) < 0 ||
        setsockopt(c->fd, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &off, sizeof off) < 0 ||
        bind(c->fd, (struct sockaddr*)&a, sizeof a) < 0) { perror("bind/setsockopt"); close(c->fd); return -1; }
    return 0;
}

void SocketCan_Close(SocketCan* c) { if (c->fd >= 0) close(c->fd); c->fd = -1; }

static int Send(uint32_t id, const uint8_t* data, uint8_t dlc, void* ctx) {
    struct can_frame f;
    memset(&f, 0, sizeof f);
    f.can_id = id > CAN_SFF_MASK ? (id | CAN_EFF_FLAG) : id;
    f.can_dlc = dlc;
    memcpy(f.data, data, dlc);
    return write(((SocketCan*)ctx)->fd, &f, sizeof f) == (ssize_t)sizeof f ? 0 : -1;
}

static int Recv(uint32_t* id, uint8_t* data, uint8_t* dlc, uint32_t timeout_ms, void* ctx) {
    struct pollfd p = {((SocketCan*)ctx)->fd, POLLIN, 0};
    int r = poll(&p, 1, (int)timeout_ms);
    if (r <= 0) return r;
    struct can_frame f;
    if (read(p.fd, &f, sizeof f) != (ssize_t)sizeof f) return -1;
    *id = f.can_id & ((f.can_id & CAN_EFF_FLAG) ? CAN_EFF_MASK : CAN_SFF_MASK);
    *dlc = f.can_dlc > 8 ? 8 : f.can_dlc;
    memcpy(data, f.data, *dlc);
    return 1;
}

IsoTp_CanDriver SocketCan_Driver(SocketCan* c) {
    IsoTp_CanDriver d = {Send, Recv, c};
    return d;
}
