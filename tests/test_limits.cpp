/* Fixed-size buffers: oversize input must be refused (E_NOT_OK / NRC), never overflow; plus the crypto port. */
#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_SimEcu.h"
#include <cstring>

typedef std::vector<uint8_t> Bytes;

/* Header of a 0x29 0x01 request whose certificate field claims `cert_len` bytes (all zero), empty challenge. */
static Bytes CertRequest(size_t cert_len) {
    Bytes b = {0x29, 0x01, 0x00, uint8_t(cert_len >> 8), uint8_t(cert_len)};
    b.insert(b.end(), cert_len, 0);
    b.insert(b.end(), {0x00, 0x00});
    return b;
}

TEST(CodecLimits, DecodeCheckedAgainstBufferSizes) {
    Uds29_Req r;
    Bytes ok = CertRequest(UDS29_MAX_CERT_LEN), big = CertRequest(UDS29_MAX_CERT_LEN + 1);
    EXPECT_TRUE(Uds29_Codec_DecodeRequest(ok.data(), ok.size(), &r));
    EXPECT_EQ(r.cert_len, UDS29_MAX_CERT_LEN);
    EXPECT_FALSE(Uds29_Codec_DecodeRequest(big.data(), big.size(), &r));
    /* challenge field one above its buffer */
    Bytes ch = {0x29, 0x01, 0x00, 0x00, 0x00, 0x00, uint8_t(UDS29_MAX_CHALLENGE_LEN + 1)};
    ch.insert(ch.end(), UDS29_MAX_CHALLENGE_LEN + 1, 0);
    EXPECT_FALSE(Uds29_Codec_DecodeRequest(ch.data(), ch.size(), &r));
    /* length field claims 0xFFFF bytes that are not there */
    const uint8_t huge[] = {0x69, 0x01, 0x11, 0xFF, 0xFF, 0x00};
    Uds29_Resp rs;
    EXPECT_FALSE(Uds29_Codec_DecodeResponse(huge, sizeof huge, &rs));
}

TEST(CodecLimits, EncodeRefusesSmallOutputAndOversizeField) {
    Uds29_Req r{}; r.sub = 0x01; r.cert_len = 100;
    uint8_t out[UDS29_MAX_MSG_LEN];
    EXPECT_EQ(Uds29_Codec_EncodeRequest(&r, out, 50), 0u);   /* does not fit */
    EXPECT_EQ(Uds29_Codec_EncodeRequest(&r, out, sizeof out), 2u + 1u + 2u + 100u + 2u);
    r.challenge_len = UDS29_MAX_CHALLENGE_LEN + 1;
    EXPECT_EQ(Uds29_Codec_EncodeRequest(&r, out, sizeof out), 0u);
    Uds29_Resp n{}; n.neg = true;
    EXPECT_EQ(Uds29_Codec_EncodeResponse(&n, out, 2), 0u);
}

/* Transport returning a canned response. */
struct Canned { Bytes resp; uint16_t claim_len = 0; };
static Std_ReturnType CannedTransport(const uint8_t*, uint16_t, uint8_t* resp, uint16_t* resp_len, void* ctx) {
    Canned* c = static_cast<Canned*>(ctx);
    if (c->resp.size() > *resp_len) return E_NOT_OK;
    std::memcpy(resp, c->resp.data(), c->resp.size());
    *resp_len = c->claim_len ? c->claim_len : uint16_t(c->resp.size());
    return E_OK;
}

class Limits : public ::testing::Test {
protected:
    void SetUp() override {
        Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
        Uds29_ConfigType cfg{0, 32};
        ASSERT_TRUE(ecu.Init(pki));
        ASSERT_EQ(Uds29_Init(&cfg), E_OK);
        ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
    }
    void TearDown() override { Uds29_DeInit(); Uds29_SetCryptoOps(nullptr); }
    Uds29SimEcu ecu;
};

TEST_F(Limits, InitRejectsOversizeChallenge) {
    Uds29_ConfigType c{0, uint8_t(UDS29_MAX_CHALLENGE_LEN + 1)};
    EXPECT_EQ(Uds29_Init(&c), E_NOT_OK);
    c.challenge_len = UDS29_MAX_CHALLENGE_LEN;
    EXPECT_EQ(Uds29_Init(&c), E_OK);
}

TEST_F(Limits, SendRawRejectsOversizeRequest) {
    Uds29_SetTransport(Uds29SimEcu::Transport, &ecu);
    Bytes req(UDS29_MAX_MSG_LEN + 1, 0x29);
    uint8_t resp[64]; uint16_t n = sizeof resp;
    EXPECT_EQ(Uds29_SendRaw(req.data(), uint16_t(req.size()), resp, &n), E_NOT_OK);
    EXPECT_EQ(Uds29_GetLogCount(), 0u);
}

TEST_F(Limits, SimEcuAnswersOversizeCertWithIncorrectLength) {
    Uds29_SetTransport(Uds29SimEcu::Transport, &ecu);
    Bytes req = CertRequest(UDS29_MAX_CERT_LEN + 1);
    uint8_t resp[64]; uint16_t n = sizeof resp;
    ASSERT_EQ(Uds29_SendRaw(req.data(), uint16_t(req.size()), resp, &n), E_OK);
    ASSERT_EQ(n, 3u);
    EXPECT_EQ(resp[0], 0x7F); EXPECT_EQ(resp[2], UDS29_NRC_INCORRECT_LENGTH);
}

TEST_F(Limits, OversizeServerFieldFailsTheSession) {
    Canned c;
    /* well-formed on the wire, but the challenge exceeds UDS29_MAX_CHALLENGE_LEN */
    c.resp = {0x69, 0x01, 0x11, 0x00, uint8_t(UDS29_MAX_CHALLENGE_LEN + 1)};
    c.resp.insert(c.resp.end(), UDS29_MAX_CHALLENGE_LEN + 1, 0xAB);
    c.resp.insert(c.resp.end(), {0x00, 0x00});
    Uds29_SetTransport(CannedTransport, &c);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
}

TEST_F(Limits, TransportReportingMoreThanItsBufferIsRejected) {
    Canned c; c.resp = {0x69, 0x08, 0x02}; c.claim_len = UDS29_MAX_MSG_LEN + 100;
    Uds29_SetTransport(CannedTransport, &c);
    const uint8_t req[] = {0x29, 0x08};
    uint8_t resp[UDS29_MAX_MSG_LEN]; uint16_t n = sizeof resp;
    EXPECT_EQ(Uds29_SendRaw(req, sizeof req, resp, &n), E_NOT_OK);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK); /* same through the state machine */
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
}

TEST_F(Limits, LogIsARingOfLogDepthEntries) {
    Canned c; c.resp = {0x69, 0x08, 0x02};
    Uds29_SetTransport(CannedTransport, &c);
    const unsigned sends = UDS29_LOG_DEPTH; /* 2 entries each */
    for (unsigned i = 0; i < sends; i++) {
        uint8_t req[] = {0x29, uint8_t(i)};
        uint8_t resp[16]; uint16_t n = sizeof resp;
        ASSERT_EQ(Uds29_SendRaw(req, sizeof req, resp, &n), E_OK);
    }
    ASSERT_EQ(Uds29_GetLogCount(), UDS29_LOG_DEPTH);
    uint8_t buf[16]; uint16_t n; Uds29_DirectionType dir;
    ASSERT_EQ(Uds29_GetLogEntry(0, &dir, buf, sizeof buf, &n), E_OK);   /* oldest kept = TX of request #(sends/2) */
    EXPECT_EQ(dir, UDS29_DIR_TX); EXPECT_EQ(buf[1], sends / 2);
    ASSERT_EQ(Uds29_GetLogEntry(UDS29_LOG_DEPTH - 1, &dir, buf, sizeof buf, &n), E_OK);
    EXPECT_EQ(dir, UDS29_DIR_RX);
    EXPECT_NE(Uds29_GetLogEntry(UDS29_LOG_DEPTH, &dir, buf, sizeof buf, &n), E_OK);
    uint8_t tiny[1];
    ASSERT_EQ(Uds29_GetLogEntry(0, &dir, tiny, sizeof tiny, &n), E_OK); /* truncated to the caller's capacity */
    EXPECT_EQ(n, 1u);
}

TEST_F(Limits, CryptoPortRespectsCapacities) {
    Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
    uint8_t cert[UDS29_MAX_CERT_LEN]; uint16_t n = 0;
    EXPECT_EQ(Uds29_Crypto_LoadIdentity(&pki, "tester", cert, 100, &n), nullptr); /* cert does not fit */
    void* id = Uds29_Crypto_LoadIdentity(&pki, "tester", cert, sizeof cert, &n);
    ASSERT_NE(id, nullptr);
    uint8_t data[8] = {1}, sig[UDS29_MAX_SIG_LEN]; uint16_t sl = 0;
    EXPECT_EQ(Uds29_Crypto_Sign(id, data, sizeof data, sig, 8, &sl), E_NOT_OK); /* signature does not fit */
    ASSERT_EQ(Uds29_Crypto_Sign(id, data, sizeof data, sig, sizeof sig, &sl), E_OK);
    EXPECT_LE(sl, UDS29_MAX_SIG_LEN);
    EXPECT_EQ(Uds29_Crypto_Verify(cert, n, data, sizeof data, sig, sl), E_OK);
    EXPECT_EQ(Uds29_Crypto_Verify(cert, n, data, sizeof data, sig, 0), E_NOT_OK);
    EXPECT_EQ(Uds29_Crypto_Verify(cert, 0, data, sizeof data, sig, sl), E_NOT_OK);
    Uds29_Crypto_FreeIdentity(id);
}

/* Custom backend registered through the port: forwards to the built-in one and counts calls. */
struct Counting { const Uds29_CryptoOpsType* inner; int calls = 0; };
static Counting g_cnt;
static const Uds29_CryptoOpsType* In(void* c) { Counting* k = static_cast<Counting*>(c); k->calls++; return k->inner; }
static Uds29_CryptoOpsType CountingOps() {
    Uds29_CryptoOpsType o{};
    o.ctx = &g_cnt;
    o.load_identity = [](void* c, const Uds29_PkiConfigType* cfg, uint8_t* d, uint16_t cap, uint16_t* l) { auto* i = In(c); return i->load_identity(i->ctx, cfg, d, cap, l); };
    o.free_identity = [](void* c, void* id) { auto* i = In(c); i->free_identity(i->ctx, id); };
    o.verify_peer_cert = [](void* c, void* id, const uint8_t* d, uint16_t l, int64_t at) { auto* i = In(c); return i->verify_peer_cert(i->ctx, id, d, l, at); };
    o.sign = [](void* c, void* id, const uint8_t* d, uint16_t l, uint8_t* s, uint16_t cap, uint16_t* sl) { auto* i = In(c); return i->sign(i->ctx, id, d, l, s, cap, sl); };
    o.verify = [](void* c, const uint8_t* ce, uint16_t cl, const uint8_t* d, uint16_t l, const uint8_t* s, uint16_t sl) { auto* i = In(c); return i->verify(i->ctx, ce, cl, d, l, s, sl); };
    o.random = [](void* c, uint8_t* out, uint16_t n) { auto* i = In(c); return i->random(i->ctx, out, n); };
    return o;
}

TEST(CryptoPort, CustomOpsAreUsedAndValidated) {
    g_cnt = Counting{Uds29_GetCryptoOps(), 0};
    ASSERT_NE(g_cnt.inner, nullptr);
    Uds29_CryptoOpsType incomplete = CountingOps();
    incomplete.sign = nullptr;
    EXPECT_EQ(Uds29_SetCryptoOps(&incomplete), E_PARAM_POINTER);
    Uds29_CryptoOpsType ops = CountingOps();
    ASSERT_EQ(Uds29_SetCryptoOps(&ops), E_OK);
    EXPECT_EQ(Uds29_GetCryptoOps()->ctx, &g_cnt);

    Uds29SimEcu ecu;
    Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
    Uds29_ConfigType cfg{0, 32};
    ASSERT_TRUE(ecu.Init(pki));
    ASSERT_EQ(Uds29_Init(&cfg), E_OK);
    Uds29_SetTransport(Uds29SimEcu::Transport, &ecu);
    ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
    EXPECT_GT(g_cnt.calls, 6); /* load x2, random x2, verify peer, verify, sign x2 ... */
    Uds29_DeInit();
    ASSERT_EQ(Uds29_SetCryptoOps(nullptr), E_OK);
    EXPECT_NE(Uds29_GetCryptoOps()->ctx, &g_cnt);
}
