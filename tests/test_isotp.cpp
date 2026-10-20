/* Userspace ISO-TP over the in-process loopback CAN bus, and the 0x29 client <-> server exchange over it
   (two threads). Certificates make the messages multi-frame. */
#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_Server.h"
#include "isotp.h"
#include "can_loopback.h"
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

struct Link {
    CanLoop bus;
    IsoTp_CanDriver da, db;
    IsoTp a, b;                       /* a: tester (tx 0x7E0, rx 0x7E8), b: ECU (reversed) */
    Link() {
        CanLoop_Init(&bus);
        da = CanLoop_Driver(&bus, 0); db = CanLoop_Driver(&bus, 1);
        IsoTp_Init(&a, &da, 0x7E0, 0x7E8);
        IsoTp_Init(&b, &db, 0x7E8, 0x7E0);
    }
};

static std::vector<uint8_t> Pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; i++) v[i] = uint8_t(i * 7 + 3);
    return v;
}

/* Sends from a, receives on b (own thread), returns the received bytes through *got. */
static int Transfer(Link& l, const std::vector<uint8_t>& msg, std::vector<uint8_t>* got, uint16_t rx_cap = 4095) {
    std::vector<uint8_t> buf(rx_cap ? rx_cap : 1);
    uint16_t n = 0;
    int rr = -99;
    std::thread rx([&] { rr = IsoTp_Recv(&l.b, buf.data(), rx_cap, &n, 2000); });
    int sr = IsoTp_Send(&l.a, msg.data(), uint16_t(msg.size()));
    rx.join();
    if (got) got->assign(buf.begin(), buf.begin() + n);
    return sr != 0 ? sr : rr;
}

TEST(IsoTp, SingleAndMultiFrameLengths) {
    for (size_t len : {1, 6, 7, 8, 13, 14, 15, 100, 1000, 4095}) {
        Link l;
        std::vector<uint8_t> got, msg = Pattern(len);
        ASSERT_EQ(Transfer(l, msg, &got), ISOTP_OK) << len;
        EXPECT_EQ(got, msg) << len;
    }
}

TEST(IsoTp, BlockSizeAndStMin) {
    Link l;
    l.b.rx_bs = 3; l.b.rx_stmin = 1;      /* FlowControl every 3 frames, 1 ms apart */
    std::vector<uint8_t> got, msg = Pattern(100);
    auto t0 = std::chrono::steady_clock::now();
    ASSERT_EQ(Transfer(l, msg, &got), ISOTP_OK);
    EXPECT_EQ(got, msg);
    EXPECT_GE(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(10)); /* 14 CFs, STmin 1 ms */
    l.b.rx_stmin = 0xF3;                  /* 300 us */
    ASSERT_EQ(Transfer(l, msg, &got), ISOTP_OK);
    EXPECT_EQ(got, msg);
}

TEST(IsoTp, PaddingAndUnpadded) {
    Link l;
    l.a.padding = -1; l.b.padding = -1;
    std::vector<uint8_t> got, msg = Pattern(20);
    ASSERT_EQ(Transfer(l, msg, &got), ISOTP_OK);
    EXPECT_EQ(got, msg);
    Link p;                               /* padded: every frame on the bus is 8 bytes, padding byte 0xAA */
    p.a.padding = 0xAA;
    uint8_t d[8]; uint8_t dlc; uint32_t id;
    uint8_t one = 0x3E;
    ASSERT_EQ(IsoTp_Send(&p.a, &one, 1), ISOTP_OK);
    ASSERT_EQ(p.db.recv(&id, d, &dlc, 100, p.db.ctx), 1);
    EXPECT_EQ(id, 0x7E0u); EXPECT_EQ(dlc, 8);
    EXPECT_EQ(d[0], 0x01); EXPECT_EQ(d[1], 0x3E); EXPECT_EQ(d[7], 0xAA);
}

TEST(IsoTp, SenderTimesOutWithoutFlowControl) {
    Link l;
    l.a.n_bs_ms = 100;
    std::vector<uint8_t> msg = Pattern(50);
    EXPECT_EQ(IsoTp_Send(&l.a, msg.data(), uint16_t(msg.size())), ISOTP_TIMEOUT);   /* nobody answers the FF */
    EXPECT_EQ(IsoTp_Send(&l.a, msg.data(), 0), ISOTP_TOO_LONG);
    EXPECT_EQ(IsoTp_Send(&l.a, msg.data(), 4096), ISOTP_TOO_LONG);
}

TEST(IsoTp, ReceiverTimesOutOnMissingConsecutiveFrame) {
    Link l;
    l.b.n_cr_ms = 100;
    std::vector<uint8_t> msg = Pattern(50), buf(100);
    uint8_t ff[8] = {0x10, 50, 0, 1, 2, 3, 4, 5};                  /* a first frame, then silence */
    ASSERT_EQ(l.da.send(0x7E0, ff, 8, l.da.ctx), 0);
    uint16_t n;
    EXPECT_EQ(IsoTp_Recv(&l.b, buf.data(), uint16_t(buf.size()), &n, 500), ISOTP_TIMEOUT);
    EXPECT_EQ(IsoTp_Recv(&l.b, buf.data(), uint16_t(buf.size()), &n, 50), ISOTP_TIMEOUT); /* idle bus */
}

TEST(IsoTp, BadSequenceNumberAndOverflow) {
    Link l;
    std::vector<uint8_t> buf(100);
    uint16_t n;
    uint8_t ff[8] = {0x10, 20, 0, 1, 2, 3, 4, 5}, cf[8] = {0x23, 6, 7, 8, 9, 10, 11, 12}; /* SN 3 instead of 1 */
    ASSERT_EQ(l.da.send(0x7E0, ff, 8, l.da.ctx), 0);
    ASSERT_EQ(l.da.send(0x7E0, cf, 8, l.da.ctx), 0);
    EXPECT_EQ(IsoTp_Recv(&l.b, buf.data(), uint16_t(buf.size()), &n, 500), ISOTP_BAD_SEQUENCE);

    Link o;
    std::vector<uint8_t> msg = Pattern(200);
    EXPECT_EQ(Transfer(o, msg, nullptr, 100), ISOTP_OVERFLOW);      /* receiver buffer too small: FC overflow, sender fails too */
}

TEST(IsoTp, IgnoresOtherIds) {
    Link l;
    uint8_t junk[8] = {0x02, 0xAA, 0xBB};
    ASSERT_EQ(l.db.send(0x123, junk, 8, l.db.ctx), 0);              /* ECU side puts a foreign frame on the bus */
    ASSERT_EQ(l.da.send(0x555, junk, 8, l.da.ctx), 0);              /* ... and the tester too */
    std::vector<uint8_t> got, msg = Pattern(30);
    ASSERT_EQ(Transfer(l, msg, &got), ISOTP_OK);
    EXPECT_EQ(got, msg);
}

/* ── 0x29 over ISO-TP: tester in this thread, ECU in another ──
   The non-blocking client API is used on purpose: the blocking calls hold the library's single OS lock while they wait
   for the response, and the ECU thread of this same process needs that lock (see docs/transports.md). */
static std::atomic<bool> g_stop;
static bool g_sent;

static void EcuThread(IsoTp* t) {
    while (!g_stop) {
        uint8_t req[UDS29_MAX_MSG_LEN], resp[UDS29_MAX_MSG_LEN];
        uint16_t n, rn = sizeof resp;
        if (IsoTp_Recv(t, req, sizeof req, &n, 20) != ISOTP_OK) continue;
        if (Uds29Srv_HandleRequest(req, n, resp, &rn) == E_OK) IsoTp_Send(t, resp, rn);
    }
}

static Std_ReturnType TesterTx(const uint8_t* req, uint16_t len, void* ctx) {
    g_sent = true;
    return IsoTp_Send(static_cast<IsoTp*>(ctx), req, len) == ISOTP_OK ? E_OK : E_NOT_OK;
}

/* One tester cycle: send what the client queued, wait for the ECU's answer, hand it to the client. */
static bool Cycle(IsoTp* t, uint16_t* biggest) {
    g_sent = false;
    Uds29_MainFunction();
    if (!g_sent) return false;
    uint8_t resp[UDS29_MAX_MSG_LEN];
    uint16_t n = 0;
    EXPECT_EQ(IsoTp_Recv(t, resp, sizeof resp, &n, 2000), ISOTP_OK);
    if (n > *biggest) *biggest = n;
    EXPECT_EQ(Uds29_RxIndication(resp, n), E_OK);
    return true;
}

class Uds29OverIsoTp : public ::testing::TestWithParam<int> {};   /* 0 = uni, 1 = bi */

TEST_P(Uds29OverIsoTp, AuthenticatesWithMultiFrameCertificates) {
    Link l;
    l.b.rx_bs = 4; l.b.rx_stmin = 0; l.a.rx_bs = 4;
    Uds29Srv_ConfigType sc{}; sc.pki.mode = UDS29_PKI_SAMPLE;
    ASSERT_EQ(Uds29Srv_Init(&sc), E_OK);
    Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
    Uds29_ConfigType cc{0, 32};
    ASSERT_EQ(Uds29_Init(&cc), E_OK);
    ASSERT_EQ(Uds29_SetTxCallback(TesterTx, &l.a), E_OK);
    ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
    g_stop = false;
    std::thread ecu(EcuThread, &l.b);
    uint16_t biggest = 0;                                        /* the longest message of either direction */
    ASSERT_EQ(Uds29_StartAuthentication(GetParam() ? UDS29_AUTH_BIDIRECTIONAL : UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    for (int i = 0; i < 10 && Cycle(&l.a, &biggest); i++) {}
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
    EXPECT_TRUE(Uds29Srv_IsAuthenticated());
    for (uint32_t i = 0; i < Uds29_GetLogCount(); i++) {         /* requests too: the 0x01/0x02 request carries the certificate */
        Uds29_DirectionType d; uint8_t b[UDS29_MAX_MSG_LEN]; uint16_t n;
        ASSERT_EQ(Uds29_GetLogEntry(i, &d, b, sizeof b, &n), E_OK);
        if (n > biggest) biggest = n;
    }
    EXPECT_GT(biggest, 300);                                     /* far beyond a single frame */
    ASSERT_EQ(Uds29_StartDeAuthentication(), E_OK);
    for (int i = 0; i < 10 && Cycle(&l.a, &biggest); i++) {}
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
    g_stop = true;
    ecu.join();
    Uds29_DeInit();
    Uds29Srv_DeInit();
}

INSTANTIATE_TEST_SUITE_P(Modes, Uds29OverIsoTp, ::testing::Values(0, 1));
