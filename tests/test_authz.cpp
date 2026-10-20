/* Certificate-based access control: profile decoding (every encoding, OU / CN / extension sources), parser hook,
   access rules, NRCs. Extension reads go through the selected crypto backend (OpenSSL or mbedTLS). */
#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_Server.h"
#include "Uds29_Crypto.h"
#include "access_example.h"
#include <cstring>
#include <string>
#include <vector>

typedef std::vector<uint8_t> Bytes;

static Uds29_CertProfileItem Item(Uds29_AzKind k, Uds29_AzSource s, Uds29_AzEncoding e, const char* oid = nullptr) {
    Uds29_CertProfileItem i{}; i.kind = k; i.source = s; i.encoding = e; i.oid = oid; return i;
}
static Std_ReturnType Dec(Uds29_AzKind k, Uds29_AzEncoding e, const Bytes& v, Uds29_Authz* a) {
    Uds29_CertProfileItem i = Item(k, UDS29_AZ_EXTENSION_OID, e);
    return Uds29_Authz_Decode(&i, v.data(), uint16_t(v.size()), a);
}

TEST(AuthzDecode, BitStringMask) {
    Uds29_Authz a{};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x02, 0x05, 0xA0}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x05u);                                                    /* bits 0 and 2 */
    a = {};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x03, 0x07, 0x00, 0x80}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x100u);                                                   /* bit 8 */
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x02, 0x08, 0x80}, &a), E_NOT_OK); /* 8 unused bits */
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x04, 0x02, 0x00, 0x80}, &a), E_NOT_OK); /* wrong tag */
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x02, 0x00, 0x80, 0x00}, &a), E_NOT_OK); /* trailing */
    a = {};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x05, 0x00, 0, 0, 0, 0x01}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x80000000u);                                              /* bit 31 */
}

TEST(AuthzDecode, BitStringBeyond32RoleBitsFails) {
    Uds29_Authz a{};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_BITSTRING_MASK, {0x03, 0x06, 0x00, 0, 0, 0, 0, 0x80}, &a), E_NOT_OK); /* bit 32 */
}

TEST(AuthzDecode, IntegerMask) {
    Uds29_Authz a{};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_INTEGER_MASK, {0x02, 0x01, 0x05}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x05u);
    a = {};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_INTEGER_MASK, {0x02, 0x02, 0x00, 0x80}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x01u << 7);
    a = {};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_INTEGER_MASK, {0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x80000000u);
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_INTEGER_MASK, {0x02, 0x01, 0x80}, &a), E_NOT_OK);             /* negative */
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_INTEGER_MASK, {0x02, 0x05, 0x01, 0, 0, 0, 0}, &a), E_NOT_OK); /* > 32 bits */
}

TEST(AuthzDecode, OctetIds) {
    Uds29_Authz a{};
    EXPECT_EQ(Dec(UDS29_AZ_SERVICES, UDS29_AZ_OCTETS_ID8, {0x04, 0x03, 0x22, 0x2E, 0x31}, &a), E_OK);
    ASSERT_EQ(a.n_services, 3);
    EXPECT_EQ(a.services[1], 0x2E);
    EXPECT_EQ(Dec(UDS29_AZ_DIDS, UDS29_AZ_OCTETS_ID16, {0x04, 0x04, 0xF1, 0x90, 0xF1, 0x8C}, &a), E_OK);
    ASSERT_EQ(a.n_dids, 2);
    EXPECT_EQ(a.dids[0], 0xF190); EXPECT_EQ(a.dids[1], 0xF18C);
    EXPECT_EQ(Dec(UDS29_AZ_RIDS, UDS29_AZ_OCTETS_ID32, {0x04, 0x04, 0x00, 0x00, 0xFF, 0x00}, &a), E_OK);
    ASSERT_EQ(a.n_rids, 1);
    EXPECT_EQ(a.rids[0], 0xFF00);
    EXPECT_EQ(Dec(UDS29_AZ_RIDS, UDS29_AZ_OCTETS_ID32, {0x04, 0x04, 0x00, 0x01, 0x00, 0x00}, &a), E_NOT_OK); /* > 16 bit */
    EXPECT_EQ(Dec(UDS29_AZ_DIDS, UDS29_AZ_OCTETS_ID16, {0x04, 0x03, 0xF1, 0x90, 0xF1}, &a), E_NOT_OK);       /* odd length */
    EXPECT_EQ(Dec(UDS29_AZ_SERVICES, UDS29_AZ_OCTETS_ID16, {0x04, 0x02, 0x01, 0x22}, &a), E_NOT_OK);          /* 0x0122 not a SID */
    Bytes many{0x04, UDS29_MAX_ALLOW + 1u};
    many.resize(2 + UDS29_MAX_ALLOW + 1, 0x22);
    Uds29_Authz b{};
    EXPECT_EQ(Dec(UDS29_AZ_SERVICES, UDS29_AZ_OCTETS_ID8, many, &b), E_NOT_OK);                                 /* list full */
}

TEST(AuthzDecode, SequenceOfInteger) {
    Uds29_Authz a{};
    EXPECT_EQ(Dec(UDS29_AZ_RIDS, UDS29_AZ_SEQ_OF_INTEGER, {0x30, 0x07, 0x02, 0x02, 0x00, 0xFF, 0x02, 0x01, 0x05}, &a), E_OK);
    ASSERT_EQ(a.n_rids, 2);
    EXPECT_EQ(a.rids[0], 0x00FF); EXPECT_EQ(a.rids[1], 0x0005);
    a = {};
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_SEQ_OF_INTEGER, {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02}, &a), E_OK);
    EXPECT_EQ(a.roles, 0x05u);                                                    /* role bit indices 0 and 2 */
    EXPECT_EQ(Dec(UDS29_AZ_ROLE, UDS29_AZ_SEQ_OF_INTEGER, {0x30, 0x03, 0x02, 0x01, 0x20}, &a), E_NOT_OK); /* bit 32 */
    EXPECT_EQ(Dec(UDS29_AZ_RIDS, UDS29_AZ_SEQ_OF_INTEGER, {0x30, 0x03, 0x04, 0x01, 0x20}, &a), E_NOT_OK); /* not INTEGER */
}

TEST(AuthzDecode, StringMap) {
    static const Uds29_AzStringMap map[] = {{"diag", 0x01}, {"engineer", 0x02}};
    Uds29_CertProfileItem ext = Item(UDS29_AZ_ROLE, UDS29_AZ_EXTENSION_OID, UDS29_AZ_STRING_MAP);
    ext.map = map; ext.map_count = 2;
    Uds29_Authz a{};
    const Bytes utf8{0x0C, 0x04, 'd', 'i', 'a', 'g'};
    EXPECT_EQ(Uds29_Authz_Decode(&ext, utf8.data(), uint16_t(utf8.size()), &a), E_OK);
    EXPECT_EQ(a.roles, 0x01u);
    const Bytes ia5{0x16, 0x08, 'e', 'n', 'g', 'i', 'n', 'e', 'e', 'r'};
    EXPECT_EQ(Uds29_Authz_Decode(&ext, ia5.data(), uint16_t(ia5.size()), &a), E_OK);
    EXPECT_EQ(a.roles, 0x03u);                                                    /* merged */
    const Bytes other{0x0C, 0x05, 'o', 't', 'h', 'e', 'r'};
    Uds29_Authz b{};
    EXPECT_EQ(Uds29_Authz_Decode(&ext, other.data(), uint16_t(other.size()), &b), E_OK);
    EXPECT_EQ(b.roles, 0u);                                                       /* unknown string: nothing */
    const Bytes wrong{0x04, 0x04, 'd', 'i', 'a', 'g'};
    EXPECT_EQ(Uds29_Authz_Decode(&ext, wrong.data(), uint16_t(wrong.size()), &b), E_NOT_OK); /* not a string type */
    Uds29_CertProfileItem ou = ext;
    ou.source = UDS29_AZ_SUBJECT_OU;                                              /* raw characters */
    EXPECT_EQ(Uds29_Authz_Decode(&ou, reinterpret_cast<const uint8_t*>("diag"), 4, &b), E_OK);
    EXPECT_EQ(b.roles, 0x01u);
    ou.encoding = UDS29_AZ_OCTETS_ID8;                                            /* OU / CN only with STRING_MAP */
    EXPECT_EQ(Uds29_Authz_Decode(&ou, reinterpret_cast<const uint8_t*>("diag"), 4, &b), E_NOT_OK);
    /* string map on a list kind adds ids */
    static const Uds29_AzStringMap dmap[] = {{"vin", 0xF190}};
    Uds29_CertProfileItem d = Item(UDS29_AZ_DIDS, UDS29_AZ_SUBJECT_CN, UDS29_AZ_STRING_MAP);
    d.map = dmap; d.map_count = 1;
    Uds29_Authz c{};
    EXPECT_EQ(Uds29_Authz_Decode(&d, reinterpret_cast<const uint8_t*>("vin"), 3, &c), E_OK);
    ASSERT_EQ(c.n_dids, 1);
    EXPECT_EQ(c.dids[0], 0xF190);
}

/* ── real certificates through the crypto backend ── */
static Bytes CertDer(const char* who) {
    Uds29_PkiConfigType p{}; p.mode = UDS29_PKI_SAMPLE;
    uint8_t der[UDS29_MAX_CERT_LEN]; uint16_t n = 0;
    void* id = Uds29_Crypto_LoadIdentity(&p, who, der, sizeof der, &n);
    EXPECT_NE(id, nullptr) << who;
    Uds29_Crypto_FreeIdentity(id);
    return Bytes(der, der + n);
}
static Uds29_Authz FromCert(const Uds29_CertProfile& pr, const char* who) {
    Bytes d = CertDer(who);
    Uds29_Authz a;
    EXPECT_EQ(Uds29_Authz_FromCert(&pr, d.data(), uint16_t(d.size()), &a), E_OK) << who;
    return a;
}

TEST(AuthzCert, ExtensionProfile) {
    Uds29_Authz a = FromCert(kExampleProfile, "tester_workshop");
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_WORKSHOP));
    EXPECT_EQ(a.n_services + a.n_dids + a.n_rids, 0);                              /* empty = unrestricted */
    EXPECT_EQ(FromCert(kExampleProfile, "tester_engineering").roles, uint32_t(EX_ROLE_ENGINEERING));
    EXPECT_EQ(FromCert(kExampleProfile, "tester_oem").roles, uint32_t(EX_ROLE_OEM));
    a = FromCert(kExampleProfile, "tester_allowlist");
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_OEM));
    ASSERT_EQ(a.n_services, 2);
    EXPECT_EQ(a.services[0], 0x22); EXPECT_EQ(a.services[1], 0x3E);
    ASSERT_EQ(a.n_dids, 2);
    EXPECT_EQ(a.dids[0], 0xF190); EXPECT_EQ(a.dids[1], 0xF18C);
    EXPECT_EQ(a.n_rids, 0);
    a = FromCert(kExampleProfile, "tester");                                       /* the plain sample tester: no extensions */
    EXPECT_EQ(a.roles, 0u);
}

TEST(AuthzCert, IntegerMaskExtensionAndDerOid) {
    static const uint8_t oid5[] = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F, 0x1D, 0x05}; /* ...99999.29.5 */
    Uds29_CertProfileItem it = Item(UDS29_AZ_ROLE, UDS29_AZ_EXTENSION_OID, UDS29_AZ_INTEGER_MASK);
    it.oid_der = oid5; it.oid_der_len = sizeof oid5;
    Uds29_CertProfile pr{&it, 1};
    EXPECT_EQ(FromCert(pr, "tester_oem").roles, uint32_t(EX_ROLE_OEM));           /* only tester_oem has .29.5 */
    EXPECT_EQ(FromCert(pr, "tester_workshop").roles, 0u);
}

TEST(AuthzCert, SubjectOuAndCn) {
    static const Uds29_AzStringMap ou[] = {{"workshop", EX_ROLE_WORKSHOP}, {"engineering", EX_ROLE_ENGINEERING}, {"oem", EX_ROLE_OEM}};
    Uds29_CertProfileItem io = Item(UDS29_AZ_ROLE, UDS29_AZ_SUBJECT_OU, UDS29_AZ_STRING_MAP);
    io.map = ou; io.map_count = 3;
    Uds29_CertProfile p1{&io, 1};
    EXPECT_EQ(FromCert(p1, "tester_workshop").roles, uint32_t(EX_ROLE_WORKSHOP));
    EXPECT_EQ(FromCert(p1, "tester_engineering").roles, uint32_t(EX_ROLE_ENGINEERING));
    EXPECT_EQ(FromCert(p1, "tester_allowlist").roles, uint32_t(EX_ROLE_OEM));
    EXPECT_EQ(FromCert(p1, "tester").roles, 0u);                                   /* no OU at all */
    static const Uds29_AzStringMap cn[] = {{"UDS29 Sample Workshop Tester", EX_ROLE_WORKSHOP}, {"UDS29 Sample tester", 0x80}};
    Uds29_CertProfileItem ic = Item(UDS29_AZ_ROLE, UDS29_AZ_SUBJECT_CN, UDS29_AZ_STRING_MAP);
    ic.map = cn; ic.map_count = 2;
    Uds29_CertProfile p2{&ic, 1};
    EXPECT_EQ(FromCert(p2, "tester_workshop").roles, uint32_t(EX_ROLE_WORKSHOP));
    EXPECT_EQ(FromCert(p2, "tester").roles, 0x80u);
    EXPECT_EQ(FromCert(p2, "tester_oem").roles, 0u);
    /* items merge: OU role + extension allow-list */
    Uds29_CertProfileItem both[] = {io, kExampleItems[1]};
    Uds29_CertProfile p3{both, 2};
    Uds29_Authz a = FromCert(p3, "tester_allowlist");
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_OEM));
    EXPECT_EQ(a.n_services, 2);
}

TEST(AuthzCert, BadProfileAndUnsupportedExtensionOp) {
    Bytes d = CertDer("tester_workshop");
    Uds29_Authz a;
    Uds29_CertProfileItem bad = Item(UDS29_AZ_ROLE, UDS29_AZ_EXTENSION_OID, UDS29_AZ_BITSTRING_MASK, "1.3.not-an-oid");
    Uds29_CertProfile p{&bad, 1};
    EXPECT_EQ(Uds29_Authz_FromCert(&p, d.data(), uint16_t(d.size()), &a), E_NOT_OK);
    /* a value of the wrong shape: .29.1 is a BIT STRING, read as OCTETS_ID8 */
    Uds29_CertProfileItem wrong = Item(UDS29_AZ_SERVICES, UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID8, "1.3.6.1.4.1.99999.29.1");
    Uds29_CertProfile p2{&wrong, 1};
    EXPECT_EQ(Uds29_Authz_FromCert(&p2, d.data(), uint16_t(d.size()), &a), E_NOT_OK);
    /* a backend without get_extension: extension items contribute nothing */
    Uds29_CryptoOpsType ops = *Uds29_GetCryptoOps();
    ops.get_extension = nullptr;
    ASSERT_EQ(Uds29_SetCryptoOps(&ops), E_OK);
    EXPECT_EQ(Uds29_Authz_FromCert(&kExampleProfile, d.data(), uint16_t(d.size()), &a), E_OK);
    EXPECT_EQ(a.roles, 0u);
    Uds29_SetCryptoOps(nullptr);
    EXPECT_EQ(Uds29_Authz_FromCert(&kExampleProfile, d.data(), uint16_t(d.size()), &a), E_OK);
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_WORKSHOP));
}

/* ── server: authentication + access rules ── */
static std::vector<Uds29_EventType> g_sev;
static void ServerEvent(const Uds29_EventType* e) { g_sev.push_back(*e); }
static Std_ReturnType ToServer(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* n, void*) {
    return Uds29Srv_HandleRequest(req, len, resp, n);
}

class Access : public ::testing::Test {
protected:
    void Start(Uds29Srv_ConfigType c = Uds29Srv_ConfigType{}) {
        c.pki.mode = UDS29_PKI_SAMPLE;
        if (!c.profile) c.profile = &kExampleProfile;
        ASSERT_EQ(Uds29Srv_Init(&c), E_OK);
        Uds29Srv_SetEventCallback(ServerEvent);
        Uds29Srv_SetAccessRules(kExampleRules, EX_NRULES);
    }
    Std_ReturnType Login(const char* who) {
        std::string d = UDS29_SAMPLE_DIR, c = d + "/" + who + "_cert.pem", k = d + "/" + who + "_key.pem", r = d + "/root_ca.pem";
        Uds29_PkiConfigType p{}; p.mode = UDS29_PKI_USER; p.root_ca_path = r.c_str(); p.cert_path = c.c_str(); p.key_path = k.c_str();
        EXPECT_EQ(Uds29_SetPki(&p), E_OK);
        return Uds29_AuthenticateUnidirectional();
    }
    /* E_OK = allowed; else the NRC */
    int Check(const Bytes& req) {
        uint8_t nrc = 0;
        return Uds29Srv_CheckAccess(req.data(), uint16_t(req.size()), &nrc) == E_OK ? 0 : nrc;
    }
    void SetUp() override {
        g_sev.clear();
        Uds29_ConfigType cfg{0, 32};
        ASSERT_EQ(Uds29_Init(&cfg), E_OK);
        ASSERT_EQ(Uds29_SetTransport(ToServer, nullptr), E_OK);
    }
    void TearDown() override { Uds29_DeInit(); Uds29Srv_DeInit(); }
};

TEST_F(Access, UnauthenticatedGets0x34) {
    Start();
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0x34);
    EXPECT_EQ(Check({0x34, 0x00}), 0x34);
    EXPECT_EQ(Check({0x19, 0x02, 0xFF}), 0);               /* no rule for 0x19: open */
    EXPECT_EQ(Check({0x3E, 0x00}), 0);                     /* always allowed */
    EXPECT_EQ(Check({0x29, 0x01}), 0);
    Uds29_Authz a;
    EXPECT_EQ(Uds29Srv_GetAuthz(&a), E_NOT_OK);
    EXPECT_EQ(a.roles, 0u);
    ASSERT_FALSE(g_sev.empty());
    EXPECT_EQ(g_sev.back().nrc, 0x34);
    uint8_t nrc;
    EXPECT_EQ(Uds29Srv_CheckAccess(nullptr, 1, &nrc), E_PARAM_POINTER);
    EXPECT_EQ(Uds29Srv_CheckAccess((const uint8_t*)"", 0, &nrc), E_NOT_OK);
}

TEST_F(Access, RolesFromCertificates) {
    Start();
    ASSERT_EQ(Login("tester_workshop"), E_OK);
    Uds29_Authz a;
    ASSERT_EQ(Uds29Srv_GetAuthz(&a), E_OK);
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_WORKSHOP));
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0);
    EXPECT_EQ(Check({0x2E, 0xF1, 0x90, 0x41}), 0x34);      /* authenticated but the role is missing */
    EXPECT_EQ(Check({0x34, 0x00, 0x44}), 0x34);
    EXPECT_EQ(Check({0x31, 0x01, 0xFF, 0x00}), 0x34);
    EXPECT_EQ(Check({0x10, 0x03}), 0);
    EXPECT_EQ(Check({0x10, 0x83}), 0);                     /* suppressPosRspMsgIndicationBit ignored */
    EXPECT_EQ(Check({0x11, 0x01}), 0x34);
    ASSERT_EQ(Uds29_DeAuthenticate(), E_OK);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0x34);            /* authz gone with the session */
    ASSERT_EQ(Login("tester_oem"), E_OK);
    for (Bytes r : {Bytes{0x22, 0xF1, 0x90}, Bytes{0x2E, 0xF1, 0x90, 1}, Bytes{0x2E, 0xF1, 0x87, 1}, Bytes{0x34, 0}, Bytes{0x31, 1, 0xFF, 0}})
        EXPECT_EQ(Check(r), 0) << int(r[0]);
}

TEST_F(Access, CertificateAllowListsNarrow) {
    Start();
    ASSERT_EQ(Login("tester_allowlist"), E_OK);            /* OEM role, services {22,3E}, DIDs {F190,F18C} */
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90, 0xF1, 0x8C}), 0);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90, 0xF1, 0x87}), 0x34); /* second DID not allowed */
    EXPECT_EQ(Check({0x22, 0xF1, 0x87}), 0x34);
    EXPECT_EQ(Check({0x2E, 0xF1, 0x90, 0x41}), 0x34);      /* service not in the list */
    EXPECT_EQ(Check({0x19, 0x02, 0xFF}), 0x34);            /* no rule, but the list narrows it */
    EXPECT_EQ(Check({0x3E, 0x00}), 0);
    EXPECT_EQ(Check({0x22}), 0x34);                        /* truncated: identifier unknown */
}

TEST_F(Access, MultiDidAndRuleMatching) {
    static const Uds29Srv_AccessRule rules[] = {
        {0x22, 0xF190, EX_ROLE_WORKSHOP}, {0x22, 0xF18C, EX_ROLE_WORKSHOP | EX_ROLE_ENGINEERING},
        {0x31, 0xFF00, 0},                                  /* roles 0: any authenticated client */
        {0x10, 0x03, EX_ROLE_ENGINEERING}};
    Start();
    Uds29Srv_SetAccessRules(rules, 4);
    ASSERT_EQ(Login("tester_workshop"), E_OK);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90, 0xF1, 0x8C}), 0);
    EXPECT_EQ(Check({0x22, 0xF1, 0x8C, 0xF1, 0x90}), 0);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90, 0xF1, 0x87}), 0x34); /* every DID must be granted */
    EXPECT_EQ(Check({0x22, 0xF1, 0x87}), 0x34);             /* SID listed, DID not: denied */
    EXPECT_EQ(Check({0x22}), 0x34);
    EXPECT_EQ(Check({0x22, 0xF1}), 0x34);
    EXPECT_EQ(Check({0x31, 0x01, 0xFF, 0x00}), 0);
    EXPECT_EQ(Check({0x31, 0x01, 0xFF, 0x01}), 0x34);
    EXPECT_EQ(Check({0x10, 0x03}), 0x34);                   /* workshop is not engineering */
    EXPECT_EQ(Check({0x10, 0x01}), 0x34);                   /* other sub-function: no rule matches */
    EXPECT_EQ(Check({0x2E, 0xF1, 0x90, 0x41}), 0);          /* 0x2E has no rule here: open */
    Uds29Srv_SetAccessRules(nullptr, 0);
    EXPECT_EQ(Check({0x34, 0x00}), 0);                      /* policy removed */
}

TEST_F(Access, DenyNrcAndDenyUnlisted) {
    Uds29Srv_ConfigType c{};
    c.deny_nrc = 0x33;
    c.deny_unlisted_sid = true;
    Start(c);
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0x33);
    EXPECT_EQ(Check({0x19, 0x02}), 0x33);                   /* unlisted SID denied, even unauthenticated */
    EXPECT_EQ(Check({0x3E, 0x00}), 0);
    ASSERT_EQ(Login("tester_oem"), E_OK);
    EXPECT_EQ(Check({0x19, 0x02}), 0x33);                   /* ... and authenticated */
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0);
    ASSERT_FALSE(g_sev.empty());
    EXPECT_EQ(g_sev.back().nrc, 0x33);
}

static Std_ReturnType RidParser(const uint8_t*, uint16_t, Uds29_Authz* a, void* ctx) {
    int* calls = static_cast<int*>(ctx);
    ++*calls;
    a->roles = EX_ROLE_ENGINEERING;
    a->n_rids = 1; a->rids[0] = 0xFF00;
    return E_OK;
}
static Std_ReturnType FailParser(const uint8_t*, uint16_t, Uds29_Authz*, void*) { return E_NOT_OK; }
static Std_ReturnType HugeParser(const uint8_t*, uint16_t, Uds29_Authz* a, void*) { a->n_dids = UDS29_MAX_ALLOW + 1; return E_OK; }

TEST_F(Access, ParserHookOverridesProfile) {
    Start();
    int calls = 0;
    Uds29Srv_SetAuthzParser(RidParser, &calls);
    ASSERT_EQ(Login("tester_workshop"), E_OK);              /* certificate says workshop; the hook says engineering */
    EXPECT_EQ(calls, 1);
    Uds29_Authz a;
    ASSERT_EQ(Uds29Srv_GetAuthz(&a), E_OK);
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_ENGINEERING));
    EXPECT_EQ(Check({0x31, 0x01, 0xFF, 0x00}), 0);          /* engineering may run routines ... */
    EXPECT_EQ(Check({0x31, 0x01, 0xFF, 0x01}), 0x34);       /* ... but only RID FF00 (allow-list from the hook) */
    EXPECT_EQ(Check({0x22, 0xF1, 0x90}), 0);

    Uds29Srv_SetAuthzParser(FailParser, nullptr);
    g_sev.clear();
    EXPECT_EQ(Login("tester_workshop"), E_NOT_OK);
    EXPECT_FALSE(Uds29Srv_IsAuthenticated());
    bool seen = false;
    for (auto& e : g_sev) seen |= e.kind == UDS29_EVT_FAILURE && e.nrc == UDS29_NRC_CVF_INVALID_CONTENT;
    EXPECT_TRUE(seen);
    Uds29Srv_SetAuthzParser(HugeParser, nullptr);            /* a hook returning an impossible count is rejected */
    EXPECT_EQ(Login("tester_workshop"), E_NOT_OK);
    Uds29Srv_SetAuthzParser(nullptr, nullptr);              /* back to the profile */
    ASSERT_EQ(Login("tester_workshop"), E_OK);
    ASSERT_EQ(Uds29Srv_GetAuthz(&a), E_OK);
    EXPECT_EQ(a.roles, uint32_t(EX_ROLE_WORKSHOP));
}

TEST_F(Access, RequiredRolesAndMalformedExtension) {
    Uds29Srv_ConfigType c{};
    c.required_roles = EX_ROLE_ENGINEERING | EX_ROLE_OEM;
    Start(c);
    g_sev.clear();
    EXPECT_EQ(Login("tester_workshop"), E_NOT_OK);          /* authenticates fine, but lacks the scope */
    bool seen = false;
    for (auto& e : g_sev) seen |= e.kind == UDS29_EVT_FAILURE && e.nrc == UDS29_NRC_CVF_INVALID_SCOPE;
    EXPECT_TRUE(seen);
    EXPECT_EQ(Login("tester"), E_NOT_OK);                   /* no role extension at all */
    EXPECT_EQ(Login("tester_engineering"), E_OK);
    Uds29Srv_DeInit();

    /* profile that mis-reads an extension (BIT STRING as services): the certificate is rejected with 0x55 */
    static const Uds29_CertProfileItem wrong[] = {Item(UDS29_AZ_SERVICES, UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID8, "1.3.6.1.4.1.99999.29.1")};
    static const Uds29_CertProfile pw = {wrong, 1};
    Uds29Srv_ConfigType c2{};
    c2.profile = &pw;
    Start(c2);
    g_sev.clear();
    EXPECT_EQ(Login("tester_workshop"), E_NOT_OK);
    seen = false;
    for (auto& e : g_sev) seen |= e.kind == UDS29_EVT_FAILURE && e.nrc == UDS29_NRC_CVF_INVALID_CONTENT;
    EXPECT_TRUE(seen);
}
