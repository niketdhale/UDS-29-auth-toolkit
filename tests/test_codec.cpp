#include <gtest/gtest.h>
#include "Uds29_Codec.h"
#include <cstring>
#include <vector>

typedef std::vector<uint8_t> Bytes;

/* Fills a fixed field: n bytes of value v. */
static void Fill(uint8_t* d, uint16_t& len, size_t n, uint8_t v) { std::memset(d, v, n); len = uint16_t(n); }
static void Put(uint8_t* d, uint16_t& len, Bytes b) { std::memcpy(d, b.data(), b.size()); len = uint16_t(b.size()); }

static Bytes Enc(const Uds29_Req& r) { uint8_t b[UDS29_MAX_MSG_LEN]; return Bytes(b, b + Uds29_Codec_EncodeRequest(&r, b, sizeof b)); }
static Bytes Enc(const Uds29_Resp& r) { uint8_t b[UDS29_MAX_MSG_LEN]; return Bytes(b, b + Uds29_Codec_EncodeResponse(&r, b, sizeof b)); }
static bool Dec(const Bytes& w, Uds29_Req& r) { return Uds29_Codec_DecodeRequest(w.data(), w.size(), &r); }
static bool Dec(const Bytes& w, Uds29_Resp& r) { return Uds29_Codec_DecodeResponse(w.data(), w.size(), &r); }

static Uds29_Req FullReq(uint8_t sub) {
    Uds29_Req r{}; r.sub = sub; r.comm = 0x01; r.eval_id = 0x1234;
    std::memset(r.alg, 0xA5, sizeof r.alg);
    Fill(r.cert, r.cert_len, 5, 1); Fill(r.challenge, r.challenge_len, 3, 2); Fill(r.pown, r.pown_len, 4, 3);
    Fill(r.eph, r.eph_len, 2, 4); Fill(r.addl, r.addl_len, 1, 5);
    return r;
}

TEST(Codec, RequestRoundTripAllSubFunctions) {
    for (uint8_t sub = 0; sub <= 8; ++sub) {
        Uds29_Req in = FullReq(sub), out;
        Bytes w = Enc(in);
        ASSERT_FALSE(w.empty()) << int(sub);
        EXPECT_EQ(w[0], 0x29); EXPECT_EQ(w[1], sub);
        ASSERT_TRUE(Dec(w, out)) << int(sub);
        EXPECT_EQ(Enc(out), w) << int(sub); /* re-encode is identical */
    }
}

TEST(Codec, ResponseRoundTripAllSubFunctions) {
    for (uint8_t sub = 0; sub <= 8; ++sub) {
        Uds29_Resp in{}; in.sub = sub; in.ret = 0x11;
        std::memset(in.alg, 0x5A, sizeof in.alg);
        Fill(in.cert, in.cert_len, 5, 1); Fill(in.challenge, in.challenge_len, 3, 2); Fill(in.pown, in.pown_len, 4, 3);
        Fill(in.eph, in.eph_len, 2, 4); Fill(in.session_key, in.session_key_len, 6, 5); Fill(in.addl, in.addl_len, 1, 6);
        Bytes w = Enc(in);
        ASSERT_FALSE(w.empty());
        EXPECT_EQ(w[0], 0x69); EXPECT_EQ(w[1], sub); EXPECT_EQ(w[2], 0x11);
        Uds29_Resp out;
        ASSERT_TRUE(Dec(w, out)) << int(sub);
        EXPECT_EQ(Enc(out), w) << int(sub);
    }
}

TEST(Codec, ByteLayouts) {
    Uds29_Req r{}; r.sub = 0x01; r.comm = 0x02; Put(r.cert, r.cert_len, {0xAA, 0xBB}); Put(r.challenge, r.challenge_len, {0xCC});
    EXPECT_EQ(Enc(r), (Bytes{0x29, 0x01, 0x02, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC}));

    Uds29_Req p{}; p.sub = 0x03; Put(p.pown, p.pown_len, {0x11}); /* empty ephemeral key */
    EXPECT_EQ(Enc(p), (Bytes{0x29, 0x03, 0x00, 0x01, 0x11, 0x00, 0x00}));

    Uds29_Req c{}; c.sub = 0x05; c.comm = 0x01; std::memset(c.alg, 0x07, 16);
    EXPECT_EQ(Enc(c).size(), 2u + 1u + 16u);

    Uds29_Resp s{}; s.sub = 0x02; s.ret = 0x11;
    Put(s.challenge, s.challenge_len, {1, 2}); Put(s.cert, s.cert_len, {3}); Put(s.pown, s.pown_len, {4});
    EXPECT_EQ(Enc(s), (Bytes{0x69, 0x02, 0x11, 0, 2, 1, 2, 0, 1, 3, 0, 1, 4, 0, 0}));

    Uds29_Resp d{}; d.sub = 0x00; d.ret = 0x10;
    EXPECT_EQ(Enc(d), (Bytes{0x69, 0x00, 0x10}));
}

TEST(Codec, NegativeResponse) {
    Uds29_Resp n{}; n.neg = true; n.nrc = 0x58;
    Bytes w = Enc(n);
    EXPECT_EQ(w, (Bytes{0x7F, 0x29, 0x58}));
    Uds29_Resp out;
    ASSERT_TRUE(Dec(w, out));
    EXPECT_TRUE(out.neg); EXPECT_EQ(out.nrc, 0x58);
    const uint8_t other_sid[] = {0x7F, 0x27, 0x35};
    EXPECT_FALSE(Uds29_Codec_DecodeResponse(other_sid, 3, &out));
}

TEST(Codec, RejectsMalformed) {
    Uds29_Req r = FullReq(0x01), out;
    Bytes w = Enc(r);
    for (size_t n = 0; n < w.size(); ++n) EXPECT_FALSE(Uds29_Codec_DecodeRequest(w.data(), n, &out)) << n; /* truncated */
    w.push_back(0);
    EXPECT_FALSE(Dec(w, out)); /* trailing byte */
    const uint8_t bad_sub[] = {0x29, 0x09};
    EXPECT_FALSE(Uds29_Codec_DecodeRequest(bad_sub, 2, &out));
    const uint8_t bad_sid[] = {0x27, 0x00};
    EXPECT_FALSE(Uds29_Codec_DecodeRequest(bad_sid, 2, &out));
    Uds29_Req big = FullReq(0x01); big.cert_len = 65535; /* above the fixed buffer: refused before anything is read */
    EXPECT_TRUE(Enc(big).empty());
    Uds29_Req badsub = FullReq(0x09);
    EXPECT_TRUE(Enc(badsub).empty());
    Uds29_Resp rs;
    const uint8_t bad_resp[] = {0x69, 0x01, 0x11, 0x00, 0x05, 0x01}; /* length exceeds data */
    EXPECT_FALSE(Uds29_Codec_DecodeResponse(bad_resp, sizeof bad_resp, &rs));
}

TEST(Codec, Strings) {
    EXPECT_STREQ(Uds29_Codec_NrcToString(0x50), "certificateVerificationFailed_InvalidTimePeriod");
    EXPECT_STREQ(Uds29_Codec_NrcToString(0x58), "ownershipVerificationFailed");
    EXPECT_STREQ(Uds29_Codec_NrcToString(0xEE), "unknownNRC");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x00), "RequestAccepted");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x07), "Reserved");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x10), "DeAuthentication successful");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x12), "OwnershipVerified, AuthenticationComplete");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x13), "CertificateVerified");
    EXPECT_STREQ(Uds29_Codec_ReturnParamToString(0x99), "Unknown");
}
