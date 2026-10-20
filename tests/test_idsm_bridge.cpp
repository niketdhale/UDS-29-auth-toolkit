#include <gtest/gtest.h>
#include "Uds29.h"
#include "Uds29_IdsM.h"
#include "Uds29_SimEcu.h"
#include "IdsM.h"
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

static std::mutex g_mx;
static std::vector<IdsM_EventReportType> g_rx;
static std::vector<std::vector<uint8_t>> g_pl;
static void Dem(const IdsM_EventReportType* e) {
    std::lock_guard<std::mutex> l(g_mx);
    g_rx.push_back(*e);
    g_pl.emplace_back(e->payload, e->payload + e->payload_len);
}

class Bridge : public ::testing::Test {
protected:
    Uds29SimEcu ecu;
    Uds29_IdsM_ConfigType cfg;
    void SetUp() override {
        g_rx.clear(); g_pl.clear();
        Uds29_IdsM_GetDefaultConfig(&cfg);
        IdsM_MonitorConfigType m{};
        m.monitor_id = cfg.monitor_id; m.event_buffer_size = 16; m.enabled_in_run = true;
        ASSERT_EQ(IdsM_Init(&m, 1), E_OK);
        IdsM_SetOperatingMode(IDSM_RUN_MODE);
        IdsM_SetDemReportCallback(Dem);
        Uds29_PkiConfigType pki{}; pki.mode = UDS29_PKI_SAMPLE;
        Uds29_ConfigType uc{0, 32};
        ASSERT_TRUE(ecu.Init(pki));
        ASSERT_EQ(Uds29_Init(&uc), E_OK);
        Uds29_SetTransport(Uds29SimEcu::Transport, &ecu);
        ASSERT_EQ(Uds29_SetPki(&pki), E_OK);
    }
    void TearDown() override { Uds29_IdsM_DeInit(); Uds29_DeInit(); IdsM_DeInit(); }
    /* The IDSM worker thread forwards to the DEM callback asynchronously: wait for n events. */
    void WaitDem(size_t n) {
        for (int i = 0; i < 200; i++) {
            { std::lock_guard<std::mutex> l(g_mx); if (g_rx.size() >= n) break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(30)); /* catch unexpected extras */
        std::lock_guard<std::mutex> l(g_mx);
        EXPECT_EQ(g_rx.size(), n);
    }
};

TEST_F(Bridge, DefaultsSuccessIsSilent) {
    ASSERT_EQ(Uds29_IdsM_Init(&cfg), E_OK);
    EXPECT_EQ(Uds29_AuthenticateBidirectional(), E_OK);
    WaitDem(0);
}

TEST_F(Bridge, OwnershipFailureIsCriticalWithPayload) {
    ASSERT_EQ(Uds29_IdsM_Init(&cfg), E_OK);
    ecu.SetFault(UDS29_SIM_FAULT_BAD_SIGNATURE);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    WaitDem(1);
    ASSERT_EQ(g_rx.size(), 1u);
    EXPECT_EQ(g_rx[0].event_id, 0x2958);
    EXPECT_EQ(g_rx[0].severity, IDSM_SEVERITY_CRITICAL);
    EXPECT_EQ(g_pl[0], (std::vector<uint8_t>{0x58, 0x03, UDS29_STATE_FAILED}));
}

TEST_F(Bridge, CustomMappingAndDisable) {
    cfg.success = {0x1234, IDSM_SEVERITY_LOW, true};
    cfg.nrc[UDS29_NRC_CVF_INVALID_TIME_PERIOD].enabled = false;
    cfg.include_payload = false;
    ASSERT_EQ(Uds29_IdsM_Init(&cfg), E_OK);
    ecu.SetFault(UDS29_SIM_FAULT_EXPIRED_CERT);   /* NRC 0x50, disabled */
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_NOT_OK);
    ecu.SetFault(UDS29_SIM_FAULT_NONE);
    EXPECT_EQ(Uds29_AuthenticateUnidirectional(), E_OK);
    WaitDem(1);
    ASSERT_EQ(g_rx.size(), 1u);
    EXPECT_EQ(g_rx[0].event_id, 0x1234);
    EXPECT_EQ(g_rx[0].payload_len, 0);
}
