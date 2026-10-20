#include <gtest/gtest.h>
#include "Uds29_SimEcu.h"
#include <cstdlib>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
static const std::string S = std::string(UDS29_SAMPLE_DIR) + "/";

/* Test-side RAII wrapper over the crypto port (whichever backend is built). */
class Uds29Pki {
public:
    ~Uds29Pki() { Uds29_Crypto_FreeIdentity(h_); }
    bool Load(const Uds29_PkiConfigType& cfg, const char* role = "tester") {
        Uds29_Crypto_FreeIdentity(h_);
        n_ = 0;
        h_ = Uds29_Crypto_LoadIdentity(&cfg, role, cert_, sizeof cert_, &n_);
        return h_ != nullptr;
    }
    Uds29_Bytes CertDer() const { return Uds29_Bytes(cert_, cert_ + n_); }
    Uds29_PkiResult VerifyPeer(const Uds29_Bytes& c, time_t at = 0) const {
        return Uds29_Crypto_VerifyPeer(h_, c.data(), uint16_t(c.size()), at);
    }
    bool Sign(const Uds29_Bytes& d, Uds29_Bytes& sig) const {
        uint8_t b[UDS29_MAX_SIG_LEN]; uint16_t n = 0;
        if (Uds29_Crypto_Sign(h_, d.data(), uint16_t(d.size()), b, sizeof b, &n) != E_OK) return false;
        sig.assign(b, b + n);
        return true;
    }
    static bool Verify(const Uds29_Bytes& c, const Uds29_Bytes& d, const Uds29_Bytes& sig) {
        return Uds29_Crypto_Verify(c.data(), uint16_t(c.size()), d.data(), uint16_t(d.size()), sig.data(), uint16_t(sig.size())) == E_OK;
    }
    static Uds29_Bytes Random(size_t n) {
        Uds29_Bytes b(n);
        if (Uds29_Crypto_Random(b.data(), uint16_t(n)) != E_OK) b.clear();
        return b;
    }
private:
    void* h_ = nullptr;
    uint8_t cert_[UDS29_MAX_CERT_LEN];
    uint16_t n_ = 0;
};

static Uds29_PkiConfigType Sample() { Uds29_PkiConfigType c{}; c.mode = UDS29_PKI_SAMPLE; return c; }

static Uds29_PkiConfigType User(const std::string& root, const std::string& cert, const std::string& key,
                                Uds29_PkiFormatType f = UDS29_PKI_FORMAT_PEM) {
    Uds29_PkiConfigType c{};
    c.mode = UDS29_PKI_USER; c.format = f;
    c.root_ca_path = root.c_str(); c.cert_path = cert.c_str(); c.key_path = key.c_str();
    return c;
}

TEST(Pki, LoadSampleTesterAndEcu) {
    Uds29Pki t, e;
    ASSERT_TRUE(t.Load(Sample(), "tester"));
    ASSERT_TRUE(e.Load(Sample(), "ecu"));
    EXPECT_NE(t.CertDer(), e.CertDer());
    EXPECT_EQ(t.VerifyPeer(e.CertDer()), UDS29_PKI_OK);
    EXPECT_EQ(e.VerifyPeer(t.CertDer()), UDS29_PKI_OK);
}

TEST(Pki, UserModeAndDer) {
    Uds29Pki p;
    ASSERT_TRUE(p.Load(User(S + "root_ca.pem", S + "tester_cert.pem", S + "tester_key.pem")));
    fs::path d = fs::temp_directory_path() / "uds29_pki_der";
    fs::create_directories(d);
    auto cmd = [&](const std::string& c) { return std::system(c.c_str()); };
    ASSERT_EQ(cmd("openssl x509 -in " + S + "root_ca.pem -outform DER -out " + (d / "root.der").string()), 0);
    ASSERT_EQ(cmd("openssl x509 -in " + S + "tester_cert.pem -outform DER -out " + (d / "cert.der").string()), 0);
    ASSERT_EQ(cmd("openssl pkey -in " + S + "tester_key.pem -outform DER -out " + (d / "key.der").string()), 0);
    Uds29Pki q;
    ASSERT_TRUE(q.Load(User((d / "root.der").string(), (d / "cert.der").string(), (d / "key.der").string(),
                            UDS29_PKI_FORMAT_DER)));
    EXPECT_EQ(p.CertDer(), q.CertDer());
    fs::remove_all(d);
}

TEST(Pki, LoadFailures) {
    Uds29Pki p;
    EXPECT_FALSE(p.Load(User(S + "root_ca.pem", S + "tester_cert.pem", S + "ecu_key.pem"))); /* key != cert */
    EXPECT_FALSE(p.Load(User(S + "root_ca.pem", S + "missing.pem", S + "tester_key.pem")));
    EXPECT_FALSE(p.Load(User(S + "ecu_cert.pem", S + "tester_cert.pem", S + "tester_key.pem"))); /* wrong root */
    EXPECT_FALSE(p.Load(User(S + "root_ca.pem", S + "tester_cert.pem", S + "tester_key.pem", UDS29_PKI_FORMAT_DER)));
    Uds29_PkiConfigType nul{}; nul.mode = UDS29_PKI_USER;
    EXPECT_FALSE(p.Load(nul));
}

TEST(Pki, ValidityPeriod) {
    Uds29Pki t, e;
    ASSERT_TRUE(t.Load(Sample(), "tester"));
    ASSERT_TRUE(e.Load(Sample(), "ecu"));
    time_t now = time(nullptr);
    EXPECT_EQ(t.VerifyPeer(e.CertDer(), now + 11LL * 365 * 86400), UDS29_PKI_EXPIRED);
    EXPECT_EQ(t.VerifyPeer(e.CertDer(), now - 86400LL * 365), UDS29_PKI_EXPIRED); /* not yet valid */
    EXPECT_EQ(t.VerifyPeer(e.CertDer(), now + 9LL * 365 * 86400), UDS29_PKI_OK);
    EXPECT_EQ(t.VerifyPeer(Uds29_Bytes{1, 2, 3}), UDS29_PKI_PARSE);
}

TEST(Pki, SignVerifyEcdsa) {
    Uds29Pki t, e;
    ASSERT_TRUE(t.Load(Sample(), "tester"));
    ASSERT_TRUE(e.Load(Sample(), "ecu"));
    Uds29_Bytes data = Uds29Pki::Random(32), sig;
    ASSERT_EQ(data.size(), 32u);
    ASSERT_TRUE(t.Sign(data, sig));
    EXPECT_TRUE(Uds29Pki::Verify(t.CertDer(), data, sig));
    EXPECT_FALSE(Uds29Pki::Verify(e.CertDer(), data, sig));   /* wrong signer */
    Uds29_Bytes tampered = data; tampered[0] ^= 1;
    EXPECT_FALSE(Uds29Pki::Verify(t.CertDer(), tampered, sig));
    sig.back() ^= 1;
    EXPECT_FALSE(Uds29Pki::Verify(t.CertDer(), data, sig));
    EXPECT_FALSE(Uds29Pki::Verify(t.CertDer(), data, {}));
}

TEST(Pki, SignVerifyEd25519) {
#ifdef UDS29_CRYPTO_MBEDTLS
    GTEST_SKIP() << "Ed25519 is not supported by the mbedTLS backend";
#endif
    fs::path d = fs::temp_directory_path() / "uds29_pki_ed";
    fs::create_directories(d);
    std::string k = (d / "k.pem").string(), c = (d / "c.pem").string();
    ASSERT_EQ(std::system(("openssl genpkey -algorithm ed25519 -out " + k).c_str()), 0);
    ASSERT_EQ(std::system(("openssl req -x509 -new -key " + k + " -subj /CN=ed -days 30 -out " + c).c_str()), 0);
    Uds29Pki p; /* self-signed: cert is its own root */
    ASSERT_TRUE(p.Load(User(c, c, k)));
    Uds29_Bytes data = Uds29Pki::Random(32), sig;
    ASSERT_TRUE(p.Sign(data, sig));
    EXPECT_EQ(sig.size(), 64u);
    EXPECT_TRUE(Uds29Pki::Verify(p.CertDer(), data, sig));
    data[0] ^= 1;
    EXPECT_FALSE(Uds29Pki::Verify(p.CertDer(), data, sig));
    fs::remove_all(d);
}
