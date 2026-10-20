#pragma once
#include "Uds29_Types.h"
#include "Uds29_Transport.h"

#ifdef __cplusplus
#include "Uds29_Codec.h"
#include "Uds29_Pki.h"
#include <mutex>
#include <vector>

/* Singleton client-side session manager (state machine for SID 0x29). */
class Uds29_Manager {
public:
    static Uds29_Manager& Instance() { static Uds29_Manager m; return m; }

    Std_ReturnType Init(const Uds29_ConfigType& cfg);
    Std_ReturnType DeInit();
    Std_ReturnType SetTransport(Uds29_TransportFn fn, void* ctx);
    Std_ReturnType SetPki(const Uds29_PkiConfigType& pki);
    void SetEventCallback(Uds29_EventCallback cb);
    Std_ReturnType Authenticate(bool bidirectional);
    Std_ReturnType DeAuthenticate();
    Uds29_StateType GetState();
    Std_ReturnType SendRaw(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len);
    uint32_t GetLogCount();
    Std_ReturnType GetLogEntry(uint32_t i, Uds29_DirectionType* dir, uint8_t* buf, uint16_t cap, uint16_t* len);
    void ClearLog();

private:
    Uds29_Manager() = default;
    Std_ReturnType Exchange(const Uds29_Req& rq, Uds29_Resp& rs);
    Std_ReturnType Fail(uint8_t sub, const char* why, uint8_t nrc = 0);
    Std_ReturnType Transfer(const uint8_t* tx, uint16_t n, uint8_t* rx, uint16_t* rx_n);
    void SetState(Uds29_StateType s);
    void Emit(Uds29_EventKindType k, uint8_t sub, uint8_t nrc, const char* why);
    void Log(Uds29_DirectionType d, const uint8_t* p, size_t n);

    struct LogEntry { Uds29_DirectionType dir; Uds29_Bytes data; };

    std::recursive_mutex mtx_; /* recursive: event callbacks may call back into the API */
    bool init_ = false, pki_ok_ = false;
    Uds29_ConfigType cfg_{};
    Uds29_TransportFn tp_ = nullptr;
    void* tp_ctx_ = nullptr;
    Uds29Pki pki_;
    Uds29_StateType state_ = UDS29_STATE_IDLE;
    Uds29_EventCallback cb_ = nullptr;
    std::vector<LogEntry> log_;
};
#endif
