/* Server module (Uds29Srv_*): client <-> server in-process through the transport callback. */
#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_Server.h"
#include "Uds29_Codec.h"
#include "Uds29_ServerTest.h"
#include <cstdlib>
#include <string>
#include <vector>

typedef std::vector<uint8_t> Bytes;
static std::vector<Uds29_EventType> g_cev, g_sev;
static void ClientEvent(const Uds29_EventType* e) { g_cev.push_back(*e); }
static void ServerEvent(const Uds29_EventType* e) { g_sev.push_back(*e); }
static uint32_t g_now;
static uint32_t FakeClock() { return g_now; }

static Std_ReturnType ToServer(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* n, void*) {
    return Uds29Srv_HandleRequest(req, len, resp, n);
}

/* Server request -> response bytes. */
static Bytes Ask(const Bytes& req) {
    uint8_t rx[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof rx;
    EXPECT_EQ(Uds29Srv_HandleRequest(req.data(), uint16_t(req.size()), rx, &n), E_OK);
    return Bytes(rx, rx + n);
}
/* Well-formed 0x03 request with a dummy proof. */
static Bytes Pown() {
    Uds29_Req r{}; r.sub = UDS29_SF_PROOF_OF_OWNERSHIP; r.pown_len = 8;
    uint8_t b[UDS29_MAX_MSG_LEN];
    return Bytes(b, b + Uds29_Codec_EncodeRequest(&r, b, sizeof b));
}
static Bytes Neg(uint8_t nrc) { return {0x7F, 0x29, nrc}; }

class Server : public ::testing::Test {
protected:
    void Start(const Uds29Srv_ConfigType& c) {
        ASSERT_EQ(Uds29Srv_Init(&c), E_OK);
        Uds29Srv_SetEventCallback(ServerEvent);
    }
    void StartDefault() { Uds29Srv_ConfigType c{}; c.pki.mode = UDS29_PKI_SAMPLE; Start(c); }
    void SetUp() override {
        g_cev.clear(); g_sev.clear(); g_now = 1000;
        Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
        Uds29_ConfigType cfg{0, 32};
        ASSERT_EQ(Uds29_Init(&cfg), E_OK);
        ASSERT_EQ(Uds29_SetTransport(ToServer, nullptr), E_OK);
        ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
        Uds29_SetEventCallback(ClientEvent);
    }
    void TearDown() override { Uds29Srv_SetClockForTest(nullptr); Uds29_DeInit(); Uds29Srv_DeInit(); }
};

TEST_F(Server, InitValidation) {
    EXPECT_EQ(Uds29Srv_Init(nullptr), E_PARAM_POINTER);
    uint8_t rx[16]; uint16_t n = sizeof rx; const uint8_t r[] = {0x29, 0x08};
    EXPECT_EQ(Uds29Srv_HandleRequest(r, 2, rx, &n), E_MODE_INVALID);
    Uds29Srv_ConfigType c{}; c.pki.mode = UDS29_PKI_SAMPLE;
    c.challenge_len = UDS29_MAX_CHALLENGE_LEN + 1;
    EXPECT_EQ(Uds29Srv_Init(&c), E_NOT_OK);
    c.challenge_len = 0;
    c.pki.mode = UDS29_PKI_USER; c.pki.root_ca_path = "/nonexistent"; c.pki.cert_path = "/nonexistent"; c.pki.key_path = "/nonexistent";
    EXPECT_EQ(Uds29Srv_Init(&c), E_NOT_OK);
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
}

TEST_F(Server, Unidirectional) {
    StartDefault();
    EXPECT_EQ(Uds29Srv_GetState(), UDS29_STATE_IDLE);
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    EXPECT_TRUE(Uds29Srv_IsAuthenticated());
    EXPECT_EQ(Uds29Srv_GetState(), UDS29_STATE_AUTHENTICATED);
    ASSERT_EQ(g_sev.size(), 2u); /* CERT_SENT, AUTHENTICATED */
    EXPECT_EQ(g_sev[0].state, UDS29_STATE_CERT_SENT);
    EXPECT_EQ(g_sev[1].state, UDS29_STATE_AUTHENTICATED);
    ASSERT_EQ(Uds29_DeAuthenticate(), E_OK);
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
}

TEST_F(Server, BidirectionalAndConfigurationRequest) {
    StartDefault();
    ASSERT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
    EXPECT_TRUE(Uds29Srv_IsAuthenticated());
    EXPECT_EQ(Ask({0x29, 0x08}), (Bytes{0x69, 0x08, 0x02}));
    EXPECT_EQ(Ask({0x29, 0x00}), (Bytes{0x69, 0x00, 0x10}));
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
}

TEST_F(Server, SequenceLengthAndSubFunctionErrors) {
    StartDefault();
    EXPECT_EQ(Ask(Pown()), Neg(UDS29_NRC_REQUEST_SEQUENCE_ERROR)); /* 0x03 without 0x01 */
    EXPECT_EQ(Ask({0x29}), Neg(UDS29_NRC_INCORRECT_LENGTH));
    EXPECT_EQ(Ask({0x29, 0x01, 0x00}), Neg(UDS29_NRC_INCORRECT_LENGTH));                    /* truncated */
    EXPECT_EQ(Ask({0x29, 0x08, 0x00}), Neg(UDS29_NRC_INCORRECT_LENGTH));                    /* trailing byte */
    for (uint8_t sf : {0x04, 0x05, 0x06, 0x07, 0x09, 0x7F})
        EXPECT_EQ(Ask({0x29, sf}), Neg(UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED)) << int(sf);
    ASSERT_GE(g_sev.size(), 1u);
    EXPECT_EQ(g_sev[0].kind, UDS29_EVT_FAILURE);
    EXPECT_EQ(g_sev[0].nrc, UDS29_NRC_REQUEST_SEQUENCE_ERROR);
}

TEST_F(Server, WrongOrderAfterCompletedAuthentication) {
    StartDefault();
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    EXPECT_EQ(Ask(Pown()), Neg(UDS29_NRC_REQUEST_SEQUENCE_ERROR)); /* proof only once per certificate */
    EXPECT_TRUE(Uds29Srv_IsAuthenticated()); /* a stray request does not drop the session */
}

TEST_F(Server, BadCertificate) {
    StartDefault();
    Bytes junk(40, 0x55);
    Bytes req = {0x29, 0x01, 0x00, 0x00, uint8_t(junk.size())};
    req.insert(req.end(), junk.begin(), junk.end());
    req.insert(req.end(), {0x00, 0x00});
    EXPECT_EQ(Ask(req), Neg(UDS29_NRC_CVF_INVALID_FORMAT));
    EXPECT_EQ(Uds29Srv_GetState(), UDS29_STATE_IDLE);

    Uds29Srv_SetFaultForTest(UDS29SRV_FAULT_EXPIRED_CERT, 0);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    ASSERT_FALSE(g_cev.empty());
    EXPECT_EQ(g_cev.back().nrc, UDS29_NRC_CVF_INVALID_TIME_PERIOD);
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
}

TEST_F(Server, OversizeFieldsAreIncorrectLength) {
    StartDefault();
    Bytes req = {0x29, 0x01, 0x00, uint8_t((UDS29_MAX_CERT_LEN + 1) >> 8), uint8_t(UDS29_MAX_CERT_LEN + 1)};
    req.insert(req.end(), UDS29_MAX_CERT_LEN + 1, 0);
    req.insert(req.end(), {0x00, 0x00});
    EXPECT_EQ(Ask(req), Neg(UDS29_NRC_INCORRECT_LENGTH));
    uint8_t tiny[2]; uint16_t n = sizeof tiny; const uint8_t r[] = {0x29, 0x08};
    EXPECT_EQ(Uds29Srv_HandleRequest(r, 2, tiny, &n), E_NOT_OK); /* response does not fit */
}

TEST_F(Server, AuthTimeoutReturnsToUnauthenticated) {
    Uds29Srv_ConfigType c{}; c.pki.mode = UDS29_PKI_SAMPLE; c.auth_timeout_ms = 1000;
    Start(c);
    Uds29Srv_SetClockForTest(FakeClock);
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    g_now += 999;
    Uds29Srv_MainFunction();
    EXPECT_TRUE(Uds29Srv_IsAuthenticated());
    g_now += 1;
    Uds29Srv_MainFunction();
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
    EXPECT_EQ(Uds29Srv_GetState(), UDS29_STATE_IDLE);
    ASSERT_EQ(g_sev.back().kind, UDS29_EVT_FAILURE);
    EXPECT_EQ(g_sev.back().nrc, 0);

    /* HandleRequest enforces it too, even if MainFunction is never called */
    ASSERT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    g_now += 1000;
    EXPECT_EQ(Ask({0x29, 0x08}), (Bytes{0x69, 0x08, 0x02}));
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
}

TEST_F(Server, FaultInjection) {
    StartDefault();
    Uds29Srv_SetFaultForTest(UDS29SRV_FAULT_BAD_SIGNATURE, 0);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    EXPECT_EQ(g_cev.back().nrc, UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED);
    Uds29Srv_SetFaultForTest(UDS29SRV_FAULT_FORCE_NRC, 0x34);
    EXPECT_EQ(Ask({0x29, 0x08}), Neg(0x34));
    Uds29Srv_SetFaultForTest(UDS29SRV_FAULT_NONE, 0);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
}

/* Role check: needs the openssl command line tool to mint a tester certificate with a given OU. */
static bool MakeTester(const std::string& dir, const std::string& name, const char* ou) {
    std::string S = std::string(UDS29_SAMPLE_DIR) + "/", k = dir + "/" + name;
    std::string cmd =
        "openssl ecparam -name prime256v1 -genkey -noout -out " + k + "_key.pem >/dev/null 2>&1 && "
        "openssl req -new -key " + k + "_key.pem -subj '/CN=tester/OU=" + ou + "' -out " + k + ".csr >/dev/null 2>&1 && "
        "printf 'basicConstraints=CA:FALSE\\nkeyUsage=digitalSignature\\n' > " + k + ".ext && "
        "openssl x509 -req -in " + k + ".csr -CA " + S + "root_ca.pem -CAkey " + S + "root_ca_key.pem -CAcreateserial "
        "-CAserial " + k + ".srl -sha256 -days 30 -extfile " + k + ".ext -out " + k + "_cert.pem >/dev/null 2>&1";
    return std::system(cmd.c_str()) == 0;
}

/* required_roles + a profile reading the role from the subject OU ("diag" -> bit 0) */
static const Uds29_AzStringMap kOuMap[] = {{"diag", 1}};
static const Uds29_CertProfileItem kOuItem[] = {{UDS29_AZ_ROLE, UDS29_AZ_SUBJECT_OU, UDS29_AZ_STRING_MAP, nullptr, nullptr, 0, kOuMap, 1}};
static const Uds29_CertProfile kOuProfile = {kOuItem, 1};

TEST_F(Server, RequiredRoleFromSubjectOu) {
    char tmpl[] = "/tmp/uds29roleXXXXXX";
    ASSERT_NE(mkdtemp(tmpl), nullptr);
    std::string dir = tmpl;
    if (!MakeTester(dir, "diag", "diag") || !MakeTester(dir, "other", "other"))
        GTEST_SKIP() << "openssl command line tool not available";
    std::string root = std::string(UDS29_SAMPLE_DIR) + "/root_ca.pem";
    Uds29Srv_ConfigType c{}; c.pki.mode = UDS29_PKI_SAMPLE; c.profile = &kOuProfile; c.required_roles = 1;
    Start(c);

    for (const char* who : {"diag", "other"}) {
        std::string crt = dir + "/" + who + "_cert.pem", key = dir + "/" + who + "_key.pem";
        Uds29_PkiConfigType p{}; p.mode = UDS29_PKI_USER; p.root_ca_path = root.c_str();
        p.cert_path = crt.c_str(); p.key_path = key.c_str();
        ASSERT_EQ(Uds29_SetPki(&p), E_OK);
        g_cev.clear();
        if (std::string(who) == "diag") {
            EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
            EXPECT_TRUE(Uds29Srv_IsAuthenticated());
        } else {
            EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
            ASSERT_FALSE(g_cev.empty());
            EXPECT_EQ(g_cev.back().nrc, UDS29_NRC_CVF_INVALID_SCOPE);
            EXPECT_FALSE(Uds29Srv_IsAuthenticated());
        }
    }
    /* the sample tester certificate has no OU at all */
    Uds29_PkiConfigType sp{}; sp.mode = UDS29_PKI_SAMPLE;
    ASSERT_EQ(Uds29_SetPki(&sp), E_OK);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    std::system(("rm -rf " + dir).c_str());
}
