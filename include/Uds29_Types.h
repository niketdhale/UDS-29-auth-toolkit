#pragma once

/* ISO 14229-1:2020 SID 0x29 (Authentication) types - Pure C compatible */
#include <stdint.h>
#include <stdbool.h>
#include "Uds29_Cfg.h"

typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint8_t  Std_ReturnType;
#define E_OK            ((uint8_t)0x00)
#define E_NOT_OK        ((uint8_t)0x01)
#define E_PARAM_POINTER ((uint8_t)0x02)
#define E_MODE_INVALID  ((uint8_t)0x04) /* not initialised / transport or PKI missing */

#define UDS29_SID_REQUEST   ((uint8_t)0x29)
#define UDS29_SID_RESPONSE  ((uint8_t)0x69)
#define UDS29_SID_NEGATIVE  ((uint8_t)0x7F)
#define UDS29_ALGORITHM_INDICATOR_LEN 16u

/* Authentication sub-functions */
typedef enum {
    UDS29_SF_DEAUTHENTICATE                   = 0x00,
    UDS29_SF_VERIFY_CERT_UNIDIRECTIONAL       = 0x01,
    UDS29_SF_VERIFY_CERT_BIDIRECTIONAL        = 0x02,
    UDS29_SF_PROOF_OF_OWNERSHIP               = 0x03,
    UDS29_SF_TRANSMIT_CERTIFICATE             = 0x04,
    UDS29_SF_REQUEST_CHALLENGE                = 0x05,
    UDS29_SF_VERIFY_POWN_UNIDIRECTIONAL       = 0x06,
    UDS29_SF_VERIFY_POWN_BIDIRECTIONAL        = 0x07,
    UDS29_SF_AUTHENTICATION_CONFIGURATION     = 0x08
} Uds29_SubFunctionType;

/* Negative response codes used by SID 0x29 */
typedef enum {
    UDS29_NRC_SUBFUNCTION_NOT_SUPPORTED   = 0x12,
    UDS29_NRC_INCORRECT_LENGTH            = 0x13,
    UDS29_NRC_REQUEST_SEQUENCE_ERROR      = 0x24,
    UDS29_NRC_REQUEST_OUT_OF_RANGE        = 0x31,
    UDS29_NRC_AUTHENTICATION_REQUIRED     = 0x34,
    UDS29_NRC_CVF_INVALID_TIME_PERIOD     = 0x50,
    UDS29_NRC_CVF_INVALID_SIGNATURE       = 0x51,
    UDS29_NRC_CVF_INVALID_CHAIN_OF_TRUST  = 0x52,
    UDS29_NRC_CVF_INVALID_TYPE            = 0x53,
    UDS29_NRC_CVF_INVALID_FORMAT          = 0x54,
    UDS29_NRC_CVF_INVALID_CONTENT         = 0x55,
    UDS29_NRC_CVF_INVALID_SCOPE           = 0x56,
    UDS29_NRC_CVF_INVALID_CERTIFICATE     = 0x57,
    UDS29_NRC_OWNERSHIP_VERIFICATION_FAILED = 0x58,
    UDS29_NRC_CHALLENGE_CALCULATION_FAILED  = 0x59,
    UDS29_NRC_SETTING_ACCESS_RIGHTS_FAILED  = 0x5A,
    UDS29_NRC_SESSION_KEY_CREATION_FAILED   = 0x5B,
    UDS29_NRC_CONFIGURATION_DATA_USAGE_FAILED = 0x5C,
    UDS29_NRC_DEAUTHENTICATION_FAILED     = 0x5D
} Uds29_NrcType;

/* authenticationReturnParameter (0x05-0x0F reserved) */
typedef enum {
    UDS29_RET_REQUEST_ACCEPTED                  = 0x00,
    UDS29_RET_GENERAL_REJECT                    = 0x01,
    UDS29_RET_AUTH_CONFIG_APCE                  = 0x02,
    UDS29_RET_AUTH_CONFIG_ACR_ASYMMETRIC        = 0x03,
    UDS29_RET_AUTH_CONFIG_ACR_SYMMETRIC         = 0x04,
    UDS29_RET_DEAUTHENTICATION_SUCCESSFUL       = 0x10,
    UDS29_RET_CERT_VERIFIED_OWNERSHIP_NECESSARY = 0x11,
    UDS29_RET_OWNERSHIP_VERIFIED_AUTH_COMPLETE  = 0x12,
    UDS29_RET_CERTIFICATE_VERIFIED              = 0x13
} Uds29_ReturnParamType;

typedef enum {
    UDS29_STATE_IDLE = 0,
    UDS29_STATE_CERT_SENT,
    UDS29_STATE_CHALLENGE_RECEIVED,
    UDS29_STATE_POWN_SENT,
    UDS29_STATE_AUTHENTICATED,
    UDS29_STATE_FAILED
} Uds29_StateType;

/* Certificate validation policy, applied to the PEER certificate (client: the ECU cert, server: the tester cert).
   All-zero = today's behaviour. See docs/certificate-validation.md. */
#define UDS29_KEY_EC_P256 0x01u          /* allowed_key_types bits (0 = any) */
#define UDS29_KEY_EC_P384 0x02u
#define UDS29_KEY_ED25519 0x04u
#define UDS29_SIG_ECDSA_SHA256 0x01u     /* allowed_sig_algs bits (0 = any): signatureAlgorithm of the peer leaf */
#define UDS29_SIG_ECDSA_SHA384 0x02u
#define UDS29_SIG_ED25519      0x04u
typedef enum {
    UDS29_TIME_SYSTEM = 0,               /* time() */
    UDS29_TIME_HOOK,                     /* the time source set with Uds29_SetTimeSource / Uds29Srv_SetTimeSource */
    UDS29_TIME_SKIP_WITH_EVENT           /* no trusted time: dates are not checked, a UDS29_EVT_WARNING is emitted */
} Uds29_TimeMode;
typedef struct {
    bool           require_key_usage_digital_signature; /* keyUsage extension present with digitalSignature */
    const uint8_t* required_eku_oid;     /* NULL = off. Full DER (06 len ...); extKeyUsage must list it. Must outlive the config */
    uint8_t        required_eku_oid_len;
    uint8_t        allowed_key_types;    /* UDS29_KEY_* mask, 0 = any */
    uint8_t        allowed_sig_algs;     /* UDS29_SIG_* mask, 0 = any */
    Uds29_TimeMode time_mode;
    bool           time_monotonic_guard; /* fail closed (UDS29_PKI_TIME_UNTRUSTED) if the time goes back by more than the tolerance */
    uint32_t       time_backstep_tolerance_s;
} Uds29_CertPolicy;

/* Proof-of-ownership data composition. The signer and the verifier must be configured identically. count 0 = the
   challenge issued by the verifier, raw (UDS29_POWN_PRESET_RAW_CHALLENGE, the default). Else the elements are
   concatenated in order. PEER / OWN are from the signer's point of view: OWN = the signer's certificate,
   PEER = the verifier's. CLIENT_CHALLENGE is empty in unidirectional authentication. */
typedef enum {
    UDS29_POWN_SERVER_CHALLENGE = 1,     /* challenge issued by the ECU */
    UDS29_POWN_CLIENT_CHALLENGE,         /* challenge sent by the tester */
    UDS29_POWN_ADDITIONAL_PARAM,         /* communicationConfiguration byte of the request */
    UDS29_POWN_PEER_CERT_HASH_SHA256,
    UDS29_POWN_OWN_CERT_HASH_SHA256
} Uds29_PownElement;
#define UDS29_POWN_MAX_ELEMENTS 5u
typedef struct { uint8_t elements[UDS29_POWN_MAX_ELEMENTS]; uint8_t count; } Uds29_PownFormat;
#define UDS29_POWN_PRESET_RAW_CHALLENGE {{0}, 0}
/* server challenge || client challenge (bidirectional) / server challenge (unidirectional). NOT claimed to be the
   exact ISO 14229-1 byte layout: configure to match your OEM / ISO spec and verify against a reference tester. */
#define UDS29_POWN_PRESET_SERVER_CLIENT_CHALLENGE {{UDS29_POWN_SERVER_CHALLENGE, UDS29_POWN_CLIENT_CHALLENGE}, 2}

/* Trusted time: unix seconds. Return E_OK with the time, anything else = no trusted time (fails closed). */
typedef Std_ReturnType (*Uds29_TimeSourceFn)(int64_t* unix_s, void* ctx);
/* One revoked certificate serial (DER INTEGER content, leading zeros ignored). */
typedef struct { const uint8_t* data; uint8_t len; } Uds29_Serial;

/* Session configuration */
typedef struct {
    uint8_t comm_config;    /* communicationConfiguration byte (0 = no secured comm) */
    uint8_t challenge_len;  /* length of the random challenge the client generates */
    Uds29_CertPolicy policy;  /* applied to the ECU certificate (bidirectional) */
    Uds29_PownFormat pown;    /* default raw challenge */
} Uds29_ConfigType;

/* PKI configuration */
typedef enum { UDS29_PKI_SAMPLE = 0, UDS29_PKI_USER = 1 } Uds29_PkiModeType;
typedef enum { UDS29_PKI_FORMAT_PEM = 0, UDS29_PKI_FORMAT_DER = 1 } Uds29_PkiFormatType;

typedef struct {
    Uds29_PkiModeType   mode;          /* SAMPLE ignores the paths below */
    const char*         root_ca_path;
    const char*         cert_path;
    const char*         key_path;
    Uds29_PkiFormatType format;        /* applies to all files */
    /* Optional, appended fields (zero = none). NULL-terminated lists are cut at the first NULL. */
    const char*         intermediate_paths[UDS29_MAX_INTERMEDIATES]; /* intermediate CAs: chained through, not trust anchors */
    const char*         crl_paths[UDS29_MAX_CRLS];                   /* CRLs: when set, revocation is checked, a missing CRL fails */
    bool                skip_validity_check; /* own-certificate check at load ignores dates (set by the core unless time_mode is SYSTEM) */
} Uds29_PkiConfigType;

/* Exchange log */
typedef enum { UDS29_DIR_TX = 0, UDS29_DIR_RX = 1 } Uds29_DirectionType;

/* Events (state changes / failures) */
typedef enum { UDS29_EVT_STATE_CHANGE = 0, UDS29_EVT_FAILURE = 1,
               UDS29_EVT_WARNING = 2 /* a check was skipped; the exchange continues (nrc 0) */ } Uds29_EventKindType;

typedef struct {
    Uds29_EventKindType kind;
    Uds29_StateType     state;         /* state after the event */
    uint8_t             sub_function;  /* sub-function in progress */
    uint8_t             nrc;           /* 0 if the failure was not an NRC */
    const char*         description;   /* static string, failures only (else "") */
} Uds29_EventType;

typedef void (*Uds29_EventCallback)(const Uds29_EventType* event);
