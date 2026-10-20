#pragma once
/* EXAMPLE OEM access-control configuration for the sample PKI (certs/sample/oem_profile.cnf).
   The OID arc 1.3.6.1.4.1.99999.29.x is NOT registered: replace 99999 with your own Private Enterprise Number.
   Included by the CLI, access_control_demo and the tests; plain C so it also compiles as C++. */
#include "Uds29_Server.h"

enum { EX_ROLE_WORKSHOP = 0x01, EX_ROLE_ENGINEERING = 0x02, EX_ROLE_OEM = 0x04 };

static const Uds29_CertProfileItem kExampleItems[] = {
    /* kind,            source,                encoding,               oid,                        oid_der, len, map, n */
    {UDS29_AZ_ROLE,     UDS29_AZ_EXTENSION_OID, UDS29_AZ_BITSTRING_MASK, "1.3.6.1.4.1.99999.29.1", 0, 0, 0, 0},
    {UDS29_AZ_SERVICES, UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID8,     "1.3.6.1.4.1.99999.29.2", 0, 0, 0, 0},
    {UDS29_AZ_DIDS,     UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID16,    "1.3.6.1.4.1.99999.29.3", 0, 0, 0, 0},
    {UDS29_AZ_RIDS,     UDS29_AZ_EXTENSION_OID, UDS29_AZ_OCTETS_ID16,    "1.3.6.1.4.1.99999.29.4", 0, 0, 0, 0},
};
static const Uds29_CertProfile kExampleProfile = {kExampleItems, 4};

/* Who may do what. A SID with rules is denied unless a rule grants it; SIDs without rules (0x19, 0x14 ...) stay open. */
static const Uds29Srv_AccessRule kExampleRules[] = {
    {0x10, UDS29_ANY, EX_ROLE_WORKSHOP | EX_ROLE_ENGINEERING | EX_ROLE_OEM}, /* session control */
    {0x11, UDS29_ANY, EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* ECU reset */
    {0x22, UDS29_ANY, EX_ROLE_WORKSHOP | EX_ROLE_ENGINEERING | EX_ROLE_OEM}, /* read any DID */
    {0x2E, 0xF190,    EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* write VIN */
    {0x2E, UDS29_ANY, EX_ROLE_OEM},                                          /* write any other DID */
    {0x27, UDS29_ANY, EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* security access */
    {0x28, UDS29_ANY, EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* communication control */
    {0x31, UDS29_ANY, EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* routines */
    {0x34, UDS29_ANY, EX_ROLE_OEM},                                          /* flashing */
    {0x36, UDS29_ANY, EX_ROLE_OEM},
    {0x37, UDS29_ANY, EX_ROLE_OEM},
    {0x85, UDS29_ANY, EX_ROLE_ENGINEERING | EX_ROLE_OEM},                    /* DTC setting */
};
#define EX_NRULES (sizeof kExampleRules / sizeof kExampleRules[0])
