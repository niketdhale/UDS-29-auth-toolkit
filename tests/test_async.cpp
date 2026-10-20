#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_Manager_Wrapper.h"
#include "Uds29_SimEcu.h"
#include <vector>

static std::vector<Uds29_Bytes> g_tx;
static std::vector<Uds29_EventType> g_events;
static uint32_t g_now;
static uint32_t FakeClock() { return g_now; }
static Std_ReturnType Capture(const uint8_t* req, uint16_t len, void*) { g_tx.emplace_back(req, req + len); return E_OK; }
static void OnEvent(const Uds29_EventType* e) { g_events.push_back(*e); }

class Async : public ::testing::Test {
protected:
    void SetUp() override {
        Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
        Uds29_ConfigType cfg{0x00, 32};
        ASSERT_TRUE(ecu.Init(pki));
        ASSERT_EQ(Uds29_Init(&cfg), E_OK);
        ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
        ASSERT_EQ(Uds29_SetTxCallback(Capture, nullptr), E_OK);
        g_tx.clear(); g_events.clear(); g_now = 1000;
        Uds29_Core_SetClockForTest(FakeClock);
        Uds29_SetEventCallback(OnEvent);
    }
    void TearDown() override { Uds29_Core_SetClockForTest(nullptr); Uds29_DeInit(); }

    /* One tester cycle: MainFunction -> captured TX -> sim ECU -> RxIndication. false if nothing was sent. */
    bool Cycle() {
        g_tx.clear();
        Uds29_MainFunction();
        if (g_tx.empty()) return false;
        uint8_t resp[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof resp;
        EXPECT_EQ(Uds29SimEcu::Transport(g_tx[0].data(), (uint16_t)g_tx[0].size(), resp, &n, &ecu), E_OK);
        EXPECT_EQ(Uds29_RxIndication(resp, n), E_OK);
        return true;
    }
    void Run() { for (int i = 0; i < 10 && Cycle(); ++i) {} }
    const Uds29_EventType* Failure() const {
        for (auto& e : g_events) if (e.kind == UDS29_EVT_FAILURE) return &e;
        return nullptr;
    }
    Uds29SimEcu ecu;
};

TEST_F(Async, UnidirectionalHappyPath) {
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_CERT_SENT);
    EXPECT_TRUE(Cycle());
    EXPECT_EQ(g_tx[0][1], 0x01);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_POWN_SENT);
    EXPECT_TRUE(Cycle());
    EXPECT_EQ(g_tx[0][1], 0x03);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
    EXPECT_FALSE(Cycle()); /* idle: nothing more to send */
    EXPECT_EQ(Failure(), nullptr);
    EXPECT_EQ(Uds29_GetLogCount(), 4u);
}

TEST_F(Async, BidirectionalHappyPathAndDeAuth) {
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL), E_OK);
    Run();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
    ASSERT_EQ(Uds29_StartDeAuthentication(), E_OK);
    Run();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    EXPECT_EQ(Failure(), nullptr);
}

TEST_F(Async, SecondStartWhileBusyAndBlockingRefused) {
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    EXPECT_EQ(Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL), E_NOT_OK);
    EXPECT_EQ(Uds29_StartDeAuthentication(), E_NOT_OK);
}

TEST_F(Async, BlockingStillWorksAfterAsync) {
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    Run();
    ASSERT_EQ(Uds29_SetTransport(Uds29SimEcu::Transport, &ecu), E_OK);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
}

TEST_F(Async, TimeoutFailsWithEvent) {
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    Uds29_MainFunction(); /* sends, starts the P2 timer */
    g_now += UDS29_P2_TIMEOUT_MS - 1;
    Uds29_MainFunction();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_CERT_SENT);
    g_now += 1;
    Uds29_MainFunction();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
    ASSERT_NE(Failure(), nullptr);
    EXPECT_STREQ(Failure()->description, "response timeout");
    EXPECT_EQ(Failure()->sub_function, 0x01);
    EXPECT_EQ(Uds29_RxIndication(g_tx[0].data(), 4), E_NOT_OK); /* late response is ignored */
    EXPECT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK); /* retry allowed */
}

TEST_F(Async, UnexpectedAndOversizeRxIndication) {
    const uint8_t r[] = {0x69, 0x01, 0x11};
    EXPECT_EQ(Uds29_RxIndication(r, sizeof r), E_NOT_OK);                  /* nothing pending */
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    EXPECT_EQ(Uds29_RxIndication(r, sizeof r), E_NOT_OK);                  /* queued, not yet sent */
    Uds29_MainFunction();
    static uint8_t big[UDS29_MAX_MSG_LEN + 1];
    EXPECT_EQ(Uds29_RxIndication(big, sizeof big), E_NOT_OK);              /* oversize */
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_CERT_SENT);                    /* still waiting */
    EXPECT_EQ(Uds29_RxIndication(nullptr, 1), E_PARAM_POINTER);
}

TEST_F(Async, FaultPropagation) {
    ecu.SetFault(UDS29_SIM_FAULT_FORCE_NRC, 0x34);
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_OK);
    Run();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
    ASSERT_NE(Failure(), nullptr);
    EXPECT_EQ(Failure()->nrc, 0x34);
    ecu.SetFault(UDS29_SIM_FAULT_BAD_SIGNATURE);
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL), E_OK);
    g_events.clear();
    Run();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
    ASSERT_NE(Failure(), nullptr);
    EXPECT_EQ(Failure()->nrc, 0); /* ECU's bad proof detected client side */
}

TEST_F(Async, StartRequiresTxCallbackAndInit) {
    Uds29_SetTxCallback(nullptr, nullptr);
    EXPECT_EQ(Uds29_StartAuthentication(UDS29_AUTH_UNIDIRECTIONAL), E_MODE_INVALID);
}

static Std_ReturnType LoopbackTx(const uint8_t* req, uint16_t len, void* ctx) {
    uint8_t resp[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof resp;
    if (Uds29SimEcu::Transport(req, len, resp, &n, ctx) != E_OK) return E_NOT_OK;
    return Uds29_RxIndication(resp, n); /* synchronous re-entry from the TX callback */
}
TEST_F(Async, ReentrantRxIndicationFromTxCallback) {
    Uds29_SetTxCallback(LoopbackTx, &ecu);
    ASSERT_EQ(Uds29_StartAuthentication(UDS29_AUTH_BIDIRECTIONAL), E_OK);
    Uds29_MainFunction(); Uds29_MainFunction();
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
}
