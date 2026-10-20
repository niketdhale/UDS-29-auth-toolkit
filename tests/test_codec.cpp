#include <gtest/gtest.h>
#include "Uds29_Codec.h"
#include <cstring>

using namespace Uds29Codec;

static Uds29_Bytes B(size_t n, uint8_t v) { return Uds29_Bytes(n, v); }

static Uds29_Req FullReq(uint8_t sub) {
    Uds29_Req r; r.sub = sub; r.comm = 0x01; r.eval_id = 0x1234;
    std::memset(r.alg, 0xA5, sizeof r.alg);
    r.cert = B(5, 1); r.challenge = B(3, 2); r.pown = B(4, 3); r.eph = B(2, 4); r.addl = B(1, 5);
    return r;
}

TEST(Codec, RequestRoundTripAllSubFunctions) {
    for (uint8_t sub = 0; sub <= 8; ++sub) {
        Uds29_Req in = FullReq(sub), out;
        Uds29_Bytes w = EncodeRequest(in);
        ASSERT_FALSE(w.empty()) << int(sub);
        EXPECT_EQ(w[0], 0x29); EXPECT_EQ(w[1], sub);
        ASSERT_TRUE(DecodeRequest(w.data(), w.size(), out)) << int(sub);
        EXPECT_EQ(EncodeRequest(out), w) << int(sub); /* re-encode is identical */
    }
}

TEST(Codec, ResponseRoundTripAllSubFunctions) {
    for (uint8_t sub = 0; sub <= 8; ++sub) {
        Uds29_Resp in; in.sub = sub; in.ret = 0x11;
        std::memset(in.alg, 0x5A, sizeof in.alg);
        in.cert = B(5, 1); in.challenge = B(3, 2); in.pown = B(4, 3); in.eph = B(2, 4);
        in.session_key = B(6, 5); in.addl = B(1, 6);
        Uds29_Bytes w = EncodeResponse(in);
        ASSERT_FALSE(w.empty());
        EXPECT_EQ(w[0], 0x69); EXPECT_EQ(w[1], sub); EXPECT_EQ(w[2], 0x11);
        Uds29_Resp out;
        ASSERT_TRUE(DecodeResponse(w.data(), w.size(), out)) << int(sub);
        EXPECT_EQ(EncodeResponse(out), w) << int(sub);
    }
}

TEST(Codec, ByteLayouts) {
    Uds29_Req r; r.sub = 0x01; r.comm = 0x02; r.cert = {0xAA, 0xBB}; r.challenge = {0xCC};
    EXPECT_EQ(EncodeRequest(r), (Uds29_Bytes{0x29, 0x01, 0x02, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC}));

    Uds29_Req p; p.sub = 0x03; p.pown = {0x11}; /* empty ephemeral key */
    EXPECT_EQ(EncodeRequest(p), (Uds29_Bytes{0x29, 0x03, 0x00, 0x01, 0x11, 0x00, 0x00}));

    Uds29_Req c; c.sub = 0x05; c.comm = 0x01; std::memset(c.alg, 0x07, 16);
    Uds29_Bytes w = EncodeRequest(c);
    EXPECT_EQ(w.size(), 2u + 1u + 16u);

    Uds29_Resp s; s.sub = 0x02; s.ret = 0x11; s.challenge = {1, 2}; s.cert = {3}; s.pown = {4}; s.eph = {};
    EXPECT_EQ(EncodeResponse(s), (Uds29_Bytes{0x69, 0x02, 0x11, 0, 2, 1, 2, 0, 1, 3, 0, 1, 4, 0, 0}));

    Uds29_Resp d; d.sub = 0x00; d.ret = 0x10;
    EXPECT_EQ(EncodeResponse(d), (Uds29_Bytes{0x69, 0x00, 0x10}));
}

TEST(Codec, NegativeResponse) {
    Uds29_Resp n; n.neg = true; n.nrc = 0x58;
    Uds29_Bytes w = EncodeResponse(n);
    EXPECT_EQ(w, (Uds29_Bytes{0x7F, 0x29, 0x58}));
    Uds29_Resp out;
    ASSERT_TRUE(DecodeResponse(w.data(), w.size(), out));
    EXPECT_TRUE(out.neg); EXPECT_EQ(out.nrc, 0x58);
    const uint8_t other_sid[] = {0x7F, 0x27, 0x35};
    EXPECT_FALSE(DecodeResponse(other_sid, 3, out));
}

TEST(Codec, RejectsMalformed) {
    Uds29_Req r = FullReq(0x01), out;
    Uds29_Bytes w = EncodeRequest(r);
    for (size_t n = 0; n < w.size(); ++n) EXPECT_FALSE(DecodeRequest(w.data(), n, out)) << n; /* truncated */
    w.push_back(0);
    EXPECT_FALSE(DecodeRequest(w.data(), w.size(), out)); /* trailing byte */
    const uint8_t bad_sub[] = {0x29, 0x09};
    EXPECT_FALSE(DecodeRequest(bad_sub, 2, out));
    const uint8_t bad_sid[] = {0x27, 0x00};
    EXPECT_FALSE(DecodeRequest(bad_sid, 2, out));
    Uds29_Req big = FullReq(0x01); big.cert = B(70000, 0);
    EXPECT_TRUE(EncodeRequest(big).empty());
    Uds29_Req badsub = FullReq(0x09);
    EXPECT_TRUE(EncodeRequest(badsub).empty());
    Uds29_Resp rs;
    const uint8_t bad_resp[] = {0x69, 0x01, 0x11, 0x00, 0x05, 0x01}; /* length exceeds data */
    EXPECT_FALSE(DecodeResponse(bad_resp, sizeof bad_resp, rs));
}

TEST(Codec, Strings) {
    EXPECT_STREQ(NrcToString(0x50), "certificateVerificationFailed_InvalidTimePeriod");
    EXPECT_STREQ(NrcToString(0x58), "ownershipVerificationFailed");
    EXPECT_STREQ(NrcToString(0xEE), "unknownNRC");
    EXPECT_STREQ(ReturnParamToString(0x00), "RequestAccepted");
    EXPECT_STREQ(ReturnParamToString(0x07), "Reserved");
    EXPECT_STREQ(ReturnParamToString(0x10), "DeAuthentication successful");
    EXPECT_STREQ(ReturnParamToString(0x12), "OwnershipVerified, AuthenticationComplete");
    EXPECT_STREQ(ReturnParamToString(0x13), "CertificateVerified");
    EXPECT_STREQ(ReturnParamToString(0x99), "Unknown");
}
