/* Certificate validation hardening: intermediates, CRL / serial revocation, key usage / EKU / algorithm policy,
   trusted time, proof-of-ownership formats. Client <-> server in-process; runs against whichever backend is built. */
#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_Server.h"
#include "Uds29_ServerTest.h"
#include "Uds29_Crypto.h"
#include "Uds29_Der.h"
#include "Uds29_Codec.h"
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
typedef std::vector<uint8_t> Bytes;
static const std::string S = std::string(UDS29_SAMPLE_DIR) + "/";

/* EXAMPLE EKUs 1.3.6.1.4.1.99999.29.100 (tester) / .101 (ECU), full DER */
static const uint8_t kEkuTester[] = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x1D, 0x64};
static const uint8_t kEkuEcu[]    = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x1D, 0x65};

struct Pki {
    std::string root, cert, key;
    std::vector<std::string> inter, crl;
    Uds29_PkiConfigType Cfg() const {
        Uds29_PkiConfigType c{};
        c.mode = UDS29_PKI_USER; c.format = UDS29_PKI_FORMAT_PEM;
        c.root_ca_path = root.c_str(); c.cert_path = cert.c_str(); c.key_path = key.c_str();
        for (size_t i = 0; i < inter.size(); i++) c.intermediate_paths[i] = inter[i].c_str();
        for (size_t i = 0; i < crl.size(); i++) c.crl_paths[i] = crl[i].c_str();
        return c;
    }
};
static Pki Sample(const std::string& name) { return Pki{S + "root_ca.pem", S + name + "_cert.pem", S + name + "_key.pem", {}, {}}; }

/* Identity handle straight on the crypto port. */
class Id {
public:
    ~Id() { Uds29_Crypto_FreeIdentity(h_); }
    bool Load(const Pki& p, bool skip_time = false) {
        Uds29_Crypto_FreeIdentity(h_);
        Uds29_PkiConfigType c = p.Cfg();
        c.skip_validity_check = skip_time;
        n_ = 0;
        h_ = Uds29_Crypto_LoadIdentity(&c, "tester", cert_, sizeof cert_, &n_);
        return h_ != nullptr;
    }
    Bytes Der() const { return Bytes(cert_, cert_ + n_); }
    Uds29_PkiResult Verify(const Bytes& c, int64_t at = 0) const { return Uds29_Crypto_VerifyPeer(h_, c.data(), uint16_t(c.size()), at); }
private:
    void* h_ = nullptr;
    uint8_t cert_[UDS29_MAX_CERT_LEN];
    uint16_t n_ = 0;
};

static Bytes CertOf(const std::string& name) {
    Id i;
    EXPECT_TRUE(i.Load(Sample(name))) << name;
    return i.Der();
}

static Bytes SerialOf(const Bytes& der) {
    Uds29_DerCert c;
    EXPECT_TRUE(Uds29_Der_ParseCert(der.data(), der.size(), &c));
    return Bytes(c.serial, c.serial + c.serial_len);
}

/* ── chain building ── */
TEST(Chain, IntermediateIsChainedThroughNotTrusted) {
    Pki p = Sample("tester_subca");
    EXPECT_FALSE(Id().Load(p)) << "sub-CA issued certificate must not load without the intermediate";
    p.inter = {S + "sub_ca.pem"};
    Id sub;
    ASSERT_TRUE(sub.Load(p));
    Id verifier, bare;
    ASSERT_TRUE(verifier.Load(Sample("ecu")));
    EXPECT_EQ(verifier.Verify(sub.Der()), UDS29_PKI_CHAIN) << "leaf only, verifier holds no intermediates";
    Pki e = Sample("ecu");
    e.inter = {S + "sub_ca.pem"};
    ASSERT_TRUE(bare.Load(e));
    EXPECT_EQ(bare.Verify(sub.Der()), UDS29_PKI_OK) << "peer sends the leaf only, verifier holds the intermediate";
    EXPECT_EQ(bare.Verify(CertOf("tester")), UDS29_PKI_OK);
}

TEST(Chain, NonCaIntermediateRejected) {
    fs::path d = fs::temp_directory_path() / "uds29_val_chain";
    fs::create_directories(d);
    std::string k = (d / "k.pem").string(), csr = (d / "c.csr").string(), c = (d / "c.pem").string();
    ASSERT_EQ(std::system(("openssl ecparam -name prime256v1 -genkey -noout -out " + k + " 2>/dev/null").c_str()), 0);
    ASSERT_EQ(std::system(("openssl req -new -key " + k + " -subj /CN=child -out " + csr + " 2>/dev/null").c_str()), 0);
    /* issued by tester_subca, which is CA:FALSE */
    ASSERT_EQ(std::system(("openssl x509 -req -in " + csr + " -CA " + S + "tester_subca_cert.pem -CAkey " + S +
                           "tester_subca_key.pem -set_serial 5 -days 30 -out " + c + " 2>/dev/null").c_str()), 0);
    Pki v = Sample("ecu");
    v.inter = {S + "sub_ca.pem", S + "tester_subca_cert.pem"};
    Id verifier;
    ASSERT_TRUE(verifier.Load(v));
    Pki p{S + "root_ca.pem", c, k, {S + "sub_ca.pem", S + "tester_subca_cert.pem"}, {}};
    EXPECT_FALSE(Id().Load(p)) << "a leaf is no CA";
    fs::remove_all(d);
}

/* ── revocation ── */
TEST(Revocation, CrlRevokesCertificate) {
    Id revoked, plain, ver;
    ASSERT_TRUE(revoked.Load(Sample("tester_revoked")));
    ASSERT_TRUE(plain.Load(Sample("tester")));
    ASSERT_TRUE(ver.Load(Sample("ecu")));
    EXPECT_EQ(ver.Verify(revoked.Der()), UDS29_PKI_OK) << "no CRL configured: not checked";
    Pki e = Sample("ecu");
    e.crl = {S + "root_crl.pem"};
    ASSERT_TRUE(ver.Load(e));
    EXPECT_EQ(ver.Verify(revoked.Der()), UDS29_PKI_REVOKED);
    EXPECT_EQ(ver.Verify(plain.Der()), UDS29_PKI_OK);
    Pki own = Sample("tester_revoked");
    own.crl = {S + "root_crl.pem"};
    EXPECT_FALSE(Id().Load(own)) << "own certificate is revoked";
}

TEST(Revocation, CrlWithIntermediate) {
    Pki e = Sample("ecu");
    e.inter = {S + "sub_ca.pem"};
    e.crl = {S + "root_crl.pem", S + "sub_ca_crl.pem"};
    Id ver, sub;
    ASSERT_TRUE(ver.Load(e));
    Pki t = Sample("tester_subca");
    t.inter = {S + "sub_ca.pem"};
    ASSERT_TRUE(sub.Load(t));
    EXPECT_EQ(ver.Verify(sub.Der()), UDS29_PKI_OK);
    EXPECT_EQ(ver.Verify(CertOf("tester_revoked")), UDS29_PKI_REVOKED);
}

TEST(Revocation, StaleCrlFailsClosed) {
    Pki e = Sample("ecu");
    e.crl = {S + "root_crl_stale.pem"};
    EXPECT_FALSE(Id().Load(e)) << "CRL past its nextUpdate: chain invalid";
    Id ver;
    EXPECT_TRUE(ver.Load(e, true)) << "dates are not checked at all (CRL nextUpdate included)";
    EXPECT_EQ(ver.Verify(CertOf("tester"), UDS29_AT_SKIP_VALIDITY), UDS29_PKI_OK);
}

/* ── client <-> server ── */
struct Ev { Uds29_EventKindType kind; uint8_t nrc; std::string why; };
static std::vector<Ev> g_cev, g_sev;
static void CEv(const Uds29_EventType* e) { g_cev.push_back({e->kind, e->nrc, e->description}); }
static void SEv(const Uds29_EventType* e) { g_sev.push_back({e->kind, e->nrc, e->description}); }
static Std_ReturnType ToServer(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* n, void*) { return Uds29Srv_HandleRequest(req, len, resp, n); }

struct Clock { int64_t t; Std_ReturnType r; };
static Std_ReturnType ClockFn(int64_t* out, void* ctx) { Clock* c = static_cast<Clock*>(ctx); *out = c->t; return c->r; }

static const Ev* Last(const std::vector<Ev>& v, Uds29_EventKindType k) {
    for (size_t i = v.size(); i--; ) if (v[i].kind == k) return &v[i];
    return nullptr;
}
static uint8_t NrcOf(const std::vector<Ev>& v) { const Ev* e = Last(v, UDS29_EVT_FAILURE); return e ? e->nrc : 0xFF; }
static std::string WhyOf(const std::vector<Ev>& v) { const Ev* e = Last(v, UDS29_EVT_FAILURE); return e ? e->why : "(none)"; }
static bool Warned(const std::vector<Ev>& v) { const Ev* e = Last(v, UDS29_EVT_WARNING); return e && e->why == "validity not checked"; }

class Val : public ::testing::Test {
protected:
    Pki cpki = Sample("tester"), spki = Sample("ecu");
    Uds29_ConfigType ccfg{0, 32};
    Uds29Srv_ConfigType scfg{};
    Uds29_TimeSourceFn ctime = nullptr, stime = nullptr;
    void *cctx = nullptr, *sctx = nullptr;
    std::vector<Uds29_Serial> crev, srev;

    void SetUp() override { g_cev.clear(); g_sev.clear(); }
    void TearDown() override { Uds29_DeInit(); Uds29Srv_DeInit(); }

    bool Auth(bool bi) {
        scfg.pki = spki.Cfg();
        if (Uds29Srv_Init(&scfg) != E_OK) { ADD_FAILURE() << "server init"; return false; }
        Uds29Srv_SetEventCallback(SEv);
        if (stime) Uds29Srv_SetTimeSource(stime, sctx);
        if (!srev.empty()) Uds29Srv_SetRevokedSerials(srev.data(), uint16_t(srev.size()));
        if (Uds29_Init(&ccfg) != E_OK || Uds29_SetTransport(ToServer, nullptr) != E_OK) { ADD_FAILURE() << "client init"; return false; }
        Uds29_SetEventCallback(CEv);
        if (ctime) Uds29_SetTimeSource(ctime, cctx);
        if (!crev.empty()) Uds29_SetRevokedSerials(crev.data(), uint16_t(crev.size()));
        Uds29_PkiConfigType p = cpki.Cfg();
        if (Uds29_SetPki(&p) != E_OK) { ADD_FAILURE() << "client PKI load"; return false; }
        return (bi ? Uds29_AuthenticateBidirectional() : Uds29_AuthenticateUnidirectional()) == E_OK;
    }
};

TEST_F(Val, DefaultsUnchanged) {
    EXPECT_TRUE(Auth(false));
    EXPECT_TRUE(Auth(true));
    EXPECT_EQ(Last(g_sev, UDS29_EVT_WARNING), nullptr);
}

TEST_F(Val, IntermediateEndToEnd) {
    cpki = Sample("tester_subca");
    cpki.inter = {S + "sub_ca.pem"};
    spki.inter = {S + "sub_ca.pem"};
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
    Uds29_DeInit(); Uds29Srv_DeInit();
    g_cev.clear(); g_sev.clear();
    spki.inter.clear();
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_cev), 0x52) << "verifier without the intermediate: invalid chain of trust";
}

TEST_F(Val, CrlRevokedTesterGetsNrc52) {
    cpki = Sample("tester_revoked");
    spki.crl = {S + "root_crl.pem"};
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x52);
    EXPECT_EQ(NrcOf(g_cev), 0x52);
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
}

TEST_F(Val, CrlOnClientChecksEcuCertificate) {
    cpki.crl = {S + "root_crl.pem"};
    EXPECT_TRUE(Auth(true)) << WhyOf(g_cev);
}

TEST_F(Val, SerialBlacklistServer) {
    Bytes ser = SerialOf(CertOf("tester"));
    srev = {Uds29_Serial{ser.data(), uint8_t(ser.size())}};
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x52);
    EXPECT_EQ(NrcOf(g_cev), 0x52);
}

TEST_F(Val, SerialBlacklistLeadingZerosAndOthers) {
    Bytes ser = SerialOf(CertOf("tester"));
    Bytes other = SerialOf(CertOf("ecu"));
    ser.insert(ser.begin(), 0x00);                     /* DER form with/without the sign octet compares equal */
    srev = {Uds29_Serial{other.data(), uint8_t(other.size())}};
    EXPECT_TRUE(Auth(false)) << "other serial listed: tester passes";
    Uds29_DeInit(); Uds29Srv_DeInit();
    srev = {Uds29_Serial{ser.data(), uint8_t(ser.size())}};
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x52);
}

TEST_F(Val, SerialBlacklistClientFailsWithEvent) {
    Bytes ser = SerialOf(CertOf("ecu"));
    crev = {Uds29_Serial{ser.data(), uint8_t(ser.size())}};
    EXPECT_FALSE(Auth(true));
    EXPECT_EQ(WhyOf(g_cev), "ECU certificate revoked");
    EXPECT_EQ(Uds29_GetState(), UDS29_STATE_FAILED);
    Uds29_SetRevokedSerials(nullptr, 0);
}

/* ── key usage / EKU ── */
TEST_F(Val, EkuAndKeyUsageAcceptTester) {
    scfg.policy.require_key_usage_digital_signature = true;
    scfg.policy.required_eku_oid = kEkuTester; scfg.policy.required_eku_oid_len = sizeof kEkuTester;
    ccfg.policy.required_eku_oid = kEkuEcu; ccfg.policy.required_eku_oid_len = sizeof kEkuEcu;
    EXPECT_TRUE(Auth(true)) << WhyOf(g_cev);
}

TEST_F(Val, EcuCertificateRejectedAsTester) {
    cpki = Sample("ecu");
    scfg.policy.required_eku_oid = kEkuTester; scfg.policy.required_eku_oid_len = sizeof kEkuTester;
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x56);
    EXPECT_EQ(NrcOf(g_cev), 0x56);
}

TEST_F(Val, ClientRejectsTesterCertificateAsEcu) {
    ccfg.policy.required_eku_oid = kEkuTester; ccfg.policy.required_eku_oid_len = sizeof kEkuTester; /* wrong purpose for an ECU */
    EXPECT_FALSE(Auth(true));
    EXPECT_EQ(WhyOf(g_cev), "ECU certificate violates the certificate policy");
}

TEST_F(Val, MissingKeyUsageAndEkuExtensions) {
    fs::path d = fs::temp_directory_path() / "uds29_val_ku";
    fs::create_directories(d);
    std::string k = (d / "k.pem").string(), csr = (d / "c.csr").string(), c = (d / "c.pem").string(), ext = (d / "e.ext").string();
    { std::ofstream(ext) << "basicConstraints=CA:FALSE\n"; }
    ASSERT_EQ(std::system(("openssl ecparam -name prime256v1 -genkey -noout -out " + k + " 2>/dev/null").c_str()), 0);
    ASSERT_EQ(std::system(("openssl req -new -key " + k + " -subj /CN=bare -out " + csr + " 2>/dev/null").c_str()), 0);
    ASSERT_EQ(std::system(("openssl x509 -req -in " + csr + " -CA " + S + "root_ca.pem -CAkey " + S + "root_ca_key.pem -set_serial 9 -days 30 -extfile " +
                           ext + " -out " + c + " 2>/dev/null").c_str()), 0);
    cpki = Pki{S + "root_ca.pem", c, k, {}, {}};
    EXPECT_TRUE(Auth(false)) << "no policy: accepted";
    Uds29_DeInit(); Uds29Srv_DeInit();
    scfg.policy.require_key_usage_digital_signature = true;
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x56);
    Uds29_DeInit(); Uds29Srv_DeInit();
    scfg.policy.require_key_usage_digital_signature = false;
    scfg.policy.required_eku_oid = kEkuTester; scfg.policy.required_eku_oid_len = sizeof kEkuTester;
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x56);
    fs::remove_all(d);
}

/* ── algorithm policy ── */
TEST_F(Val, KeyTypePolicy) {
    cpki = Sample("tester_p384");
    EXPECT_TRUE(Auth(false)) << "default: any";
    Uds29_DeInit(); Uds29Srv_DeInit();
    scfg.policy.allowed_key_types = UDS29_KEY_EC_P256;
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x56);
    Uds29_DeInit(); Uds29Srv_DeInit();
    scfg.policy.allowed_key_types = UDS29_KEY_EC_P256 | UDS29_KEY_EC_P384;
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
    Uds29_DeInit(); Uds29Srv_DeInit();
    cpki = Sample("tester");
    scfg.policy.allowed_key_types = UDS29_KEY_ED25519;
    EXPECT_FALSE(Auth(false)) << "P-256 key not in the list";
    EXPECT_EQ(NrcOf(g_sev), 0x56);
}

TEST_F(Val, SignatureAlgorithmPolicy) {
    cpki = Sample("tester_sha384");
    scfg.policy.allowed_sig_algs = UDS29_SIG_ECDSA_SHA256;
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x56);
    Uds29_DeInit(); Uds29Srv_DeInit();
    scfg.policy.allowed_sig_algs = UDS29_SIG_ECDSA_SHA256 | UDS29_SIG_ECDSA_SHA384;
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
    Uds29_DeInit(); Uds29Srv_DeInit();
    cpki = Sample("tester");
    scfg.policy.allowed_sig_algs = UDS29_SIG_ECDSA_SHA256;
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
}

/* ── trusted time ── */
static const int64_t kMid2035 = 2056320000; /* 2035-06-30 */

TEST_F(Val, FutureCertificateRejectedBySystemTime) {
    cpki = Sample("tester_future");
    ccfg.policy.time_mode = UDS29_TIME_SKIP_WITH_EVENT; /* the tester's own load must not check dates either */
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x50);
}

TEST_F(Val, HookProvidesTrustedTime) {
    Clock c{kMid2035, E_OK};
    cpki = Sample("tester_future");
    ccfg.policy.time_mode = UDS29_TIME_SKIP_WITH_EVENT;
    scfg.policy.time_mode = UDS29_TIME_HOOK;
    stime = ClockFn; sctx = &c;
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
    Uds29_DeInit(); Uds29Srv_DeInit();
    c.t = kMid2035 + 2LL * 365 * 86400;                  /* 2037: expired */
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x50);
    Uds29_DeInit(); Uds29Srv_DeInit();
    c.r = E_NOT_OK;                                      /* no trusted time: fail closed */
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x50);
    EXPECT_EQ(WhyOf(g_sev), Uds29_Codec_NrcToString(0x50));
    Uds29_DeInit(); Uds29Srv_DeInit();
    stime = nullptr;                                     /* HOOK without a hook */
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x50);
}

TEST_F(Val, SkipModeEmitsWarning) {
    cpki = Sample("tester_future");
    ccfg.policy.time_mode = UDS29_TIME_SKIP_WITH_EVENT;
    scfg.policy.time_mode = UDS29_TIME_SKIP_WITH_EVENT;
    EXPECT_TRUE(Auth(true)) << WhyOf(g_cev);
    EXPECT_TRUE(Warned(g_sev));
    EXPECT_TRUE(Warned(g_cev)) << "client skips the ECU certificate dates too";
    EXPECT_EQ(Last(g_sev, UDS29_EVT_WARNING)->nrc, 0);
}

TEST_F(Val, MonotonicGuard) {
    Clock c{kMid2035, E_OK};
    cpki = Sample("tester_future");
    ccfg.policy.time_mode = UDS29_TIME_SKIP_WITH_EVENT;
    scfg.policy.time_mode = UDS29_TIME_HOOK;
    scfg.policy.time_monotonic_guard = true;
    scfg.policy.time_backstep_tolerance_s = 60;
    stime = ClockFn; sctx = &c;
    ASSERT_TRUE(Auth(false)) << WhyOf(g_cev);
    c.t -= 30;                                           /* within the tolerance */
    EXPECT_EQ(Uds29_DeAuthenticate(), E_OK);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    c.t -= 3600;                                         /* clock went back an hour */
    EXPECT_EQ(Uds29_DeAuthenticate(), E_OK);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    EXPECT_EQ(NrcOf(g_sev), 0x50);
    c.t += 7200;                                         /* forward again */
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
}

/* ── proof of ownership ── */
TEST(Sha256, KnownAnswer) {
    uint8_t h[32];
    ASSERT_EQ(Uds29_Crypto_Sha256(reinterpret_cast<const uint8_t*>("abc"), 3, h), E_OK);
    EXPECT_EQ(h[0], 0xBA); EXPECT_EQ(h[1], 0x78); EXPECT_EQ(h[31], 0xAD);
}

TEST_F(Val, PownPresetServerClientChallenge) {
    Uds29_PownFormat f = UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE;
    ccfg.pown = f; scfg.pown = f;
    EXPECT_TRUE(Auth(true)) << WhyOf(g_cev);
    EXPECT_TRUE(Uds29_DeAuthenticate() == E_OK);
    EXPECT_TRUE(Uds29_AuthenticateUnidirectional() == E_OK);
    EXPECT_TRUE(Uds29Srv_IsAuthenticated());
}

TEST_F(Val, PownCustomWithCertHashesAndAdditionalParam) {
    Uds29_PownFormat f = {{UDS29_POWN_SERVER_CHALLENGE, UDS29_POWN_CLIENT_CHALLENGE, UDS29_POWN_ADDITIONAL_PARAM,
                           UDS29_POWN_PEER_CERT_HASH_SHA256, UDS29_POWN_OWN_CERT_HASH_SHA256}, 5};
    ccfg.pown = f; scfg.pown = f; ccfg.comm_config = 0x01;
    EXPECT_TRUE(Auth(true)) << WhyOf(g_cev);
    Uds29_DeInit(); Uds29Srv_DeInit();
    Uds29_PownFormat own = {{UDS29_POWN_SERVER_CHALLENGE, UDS29_POWN_OWN_CERT_HASH_SHA256}, 2};
    ccfg.pown = own; scfg.pown = own;
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev) << ": own certificate hash is known on both sides in unidirectional";
    Uds29_DeInit(); Uds29Srv_DeInit();
    ccfg.pown = f; scfg.pown = f;
    EXPECT_FALSE(Auth(false)) << "unidirectional: the tester does not know the ECU certificate, PEER hash unavailable";
    EXPECT_EQ(WhyOf(g_cev), "signing failed");
}

TEST_F(Val, PownMismatchGivesNrc58) {
    Uds29_PownFormat cf = {{UDS29_POWN_SERVER_CHALLENGE, UDS29_POWN_ADDITIONAL_PARAM}, 2};
    ccfg.pown = cf;                                      /* server stays on the raw challenge */
    EXPECT_FALSE(Auth(false));
    EXPECT_EQ(NrcOf(g_sev), 0x58);
    EXPECT_EQ(NrcOf(g_cev), 0x58);
}

TEST_F(Val, PownMismatchBidirectionalFailsEcuProofOnClient) {
    Uds29_PownFormat f = UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE;
    ccfg.pown = f;                                       /* ECU signs the raw client challenge */
    EXPECT_FALSE(Auth(true));
    EXPECT_EQ(WhyOf(g_cev), "ECU proof of ownership invalid");
}

TEST_F(Val, PownUnidirectionalPresetEqualsRaw) {
    Uds29_PownFormat f = UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE;
    ccfg.pown = f;                                       /* unidirectional: server challenge only, as raw */
    EXPECT_TRUE(Auth(false)) << WhyOf(g_cev);
}
