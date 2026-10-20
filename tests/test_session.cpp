#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_SimEcu.h"
#include <vector>

static std::vector<Uds29_EventType> g_events;
static void OnEvent(const Uds29_EventType* e) { g_events.push_back(*e); }

class Session : public ::testing::Test {
protected:
    void SetUp() override {
        Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
        Uds29_ConfigType cfg{0x00, 32};
        ASSERT_EQ(ecu.Init(pki), true);
        ASSERT_EQ(Uds29_Init(&cfg), E_OK);
        ASSERT_EQ(Uds29_SetTransport(Uds29SimEcu::Transport, &ecu), E_OK);
        ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
        g_events.clear();
        Uds29_SetEventCallback(OnEvent);
    }
    void TearDown() override { Uds29_DeInit(); }

    const Uds29_EventType* Failure() const {
        for (auto& e : g_events) if (e.kind == UDS29_EVT_FAILURE) return &e;
        return nullptr;
    }
    std::vector<Uds29_StateType> States() const {
        std::vector<Uds29_StateType> s;
        for (auto& e : g_events) if (e.kind == UDS29_EVT_STATE_CHANGE) s.push_back(e.state);
        return s;
    }
    /* Runs a flow with a fault; returns the failure event's NRC (0 = client-detected). */
    void ExpectFail(bool bidi, Uds29_SimFault f, uint8_t nrc, uint8_t forced = 0) {
        ecu.SetFault(f, forced);
        EXPECT_EQ(bidi ? Uds29_AuthenticateBidirectional() : Uds29_AuthenticateUnidirectional(), E_NOT_OK);
        EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
        ASSERT_NE(Failure(), nullptr);
        EXPECT_EQ(Failure()->nrc, nrc);
        EXPECT_NE(std::string(Failure()->description), "");
    }
    Uds29SimEcu ecu;
};

TEST_F(Session, UnidirectionalHappyPath) {
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
    EXPECT_EQ(States(), (std::vector<Uds29_StateType>{UDS29_STATE_CERT_SENT, UDS29_STATE_CHALLENGE_RECEIVED,
                                                      UDS29_STATE_POWN_SENT, UDS29_STATE_AUTHENTICATED}));
    ASSERT_EQ(Uds29_GetLogCount(), 4u);
    uint8_t buf[2048]; uint16_t n; Uds29_DirectionType dir;
    const uint8_t sub[4] = {0x01, 0x01, 0x03, 0x03}, sid[4] = {0x29, 0x69, 0x29, 0x69};
    for (uint32_t i = 0; i < 4; ++i) {
        ASSERT_EQ(Uds29_GetLogEntry(i, &dir, buf, sizeof buf, &n), E_OK);
        EXPECT_EQ(dir, i % 2 ? UDS29_DIR_RX : UDS29_DIR_TX);
        EXPECT_EQ(buf[0], sid[i]); EXPECT_EQ(buf[1], sub[i]);
    }
    EXPECT_EQ(buf[2], 0x12); /* last RX: OwnershipVerified, AuthenticationComplete */
    EXPECT_NE(Uds29_GetLogEntry(4, &dir, buf, sizeof buf, &n), E_OK);
}

TEST_F(Session, BidirectionalHappyPath) {
    ASSERT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
    EXPECT_EQ(Failure(), nullptr);
    uint8_t buf[2048]; uint16_t n; Uds29_DirectionType dir;
    ASSERT_EQ(Uds29_GetLogEntry(0, &dir, buf, sizeof buf, &n), E_OK);
    EXPECT_EQ(buf[1], 0x02);
}

TEST_F(Session, DeAuthenticate) {
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    ASSERT_EQ(Uds29_DeAuthenticate(), E_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    ASSERT_EQ(Uds29_AuthenticateBidirectional(), E_OK); /* re-authenticate works */
}

TEST_F(Session, ExpiredCert)       { ExpectFail(false, UDS29_SIM_FAULT_EXPIRED_CERT, 0x50); }
TEST_F(Session, ExpiredCertBi)     { ExpectFail(true,  UDS29_SIM_FAULT_EXPIRED_CERT, 0x50); }
TEST_F(Session, BadSignature)      { ExpectFail(false, UDS29_SIM_FAULT_BAD_SIGNATURE, 0x58); }
TEST_F(Session, BadSignatureBi)    { ExpectFail(true,  UDS29_SIM_FAULT_BAD_SIGNATURE, 0); }
TEST_F(Session, ChallengeMismatch)   { ExpectFail(false, UDS29_SIM_FAULT_CHALLENGE_MISMATCH, 0x58); }
TEST_F(Session, ChallengeMismatchBi) { ExpectFail(true,  UDS29_SIM_FAULT_CHALLENGE_MISMATCH, 0); }
TEST_F(Session, WrongCertFormat)     { ExpectFail(false, UDS29_SIM_FAULT_WRONG_CERT_FORMAT, 0x54); }
TEST_F(Session, WrongCertFormatBi)   { ExpectFail(true,  UDS29_SIM_FAULT_WRONG_CERT_FORMAT, 0); }
TEST_F(Session, ForcedNrc)           { ExpectFail(false, UDS29_SIM_FAULT_FORCE_NRC, 0x34, 0x34); }
TEST_F(Session, ForcedNrcBi)         { ExpectFail(true,  UDS29_SIM_FAULT_FORCE_NRC, 0x5B, 0x5B); }

TEST_F(Session, FailureStateIsLeftByRetry) {
    ecu.SetFault(UDS29_SIM_FAULT_BAD_SIGNATURE);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_NOT_OK);
    ecu.SetFault(UDS29_SIM_FAULT_NONE);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_AUTHENTICATED);
}

TEST_F(Session, SendRawIsLoggedWithoutStateChange) {
    const uint8_t req[] = {0x29, 0x08};
    uint8_t resp[64]; uint16_t n = sizeof resp;
    ASSERT_EQ(Uds29_SendRaw(req, sizeof req, resp, &n), E_OK);
    EXPECT_EQ(std::vector<uint8_t>(resp, resp + n), (std::vector<uint8_t>{0x69, 0x08, 0x02}));
    EXPECT_EQ(Uds29_GetLogCount(), 2u);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    const uint8_t bad[] = {0x29, 0x04, 0x00, 0x01, 0x00, 0x00}; /* unsupported by sim ECU */
    n = sizeof resp;
    ASSERT_EQ(Uds29_SendRaw(bad, sizeof bad, resp, &n), E_OK);
    EXPECT_EQ(resp[0], 0x7F); EXPECT_EQ(resp[2], 0x12);
    Uds29_ClearLog();
    EXPECT_EQ(Uds29_GetLogCount(), 0u);
}

TEST_F(Session, ECUSequenceErrorOnEarlyPown) {
    const uint8_t pown[] = {0x29, 0x03, 0x00, 0x01, 0xAA, 0x00, 0x00};
    uint8_t resp[64]; uint16_t n = sizeof resp;
    ASSERT_EQ(Uds29_SendRaw(pown, sizeof pown, resp, &n), E_OK);
    EXPECT_EQ(resp[2], 0x24);
}

TEST(SessionNotReady, Guards) {
    Uds29_DeInit();
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_MODE_INVALID);
    EXPECT_EQ(Uds29_Init(nullptr), E_PARAM_POINTER);
    Uds29_ConfigType cfg{0, 32};
    ASSERT_EQ(Uds29_Init(&cfg), E_OK);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_MODE_INVALID); /* no transport/PKI */
    Uds29_PkiConfigType bad{}; bad.mode = UDS29_PKI_USER; bad.root_ca_path = "/nope"; bad.cert_path = "/nope"; bad.key_path = "/nope";
    EXPECT_EQ(Uds29_SetPki(&bad), E_NOT_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_IDLE);
    Uds29_DeInit();
}
