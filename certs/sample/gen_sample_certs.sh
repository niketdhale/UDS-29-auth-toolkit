#!/bin/sh
# Generates the SAMPLE PKI (EC P-256, 10y): root CA, tester and ECU cert+key, four testers whose certificates carry
# roles / allow-lists as defined in oem_profile.cnf (EXAMPLE OIDs), plus the validation-hardening fixtures:
#   sub_ca            intermediate CA (pathlen 0) under the root; tester_subca is issued by it
#   tester_revoked    issued by the root and listed in root_crl.pem (the sub-CA has an empty CRL, sub_ca_crl.pem)
#   tester_future     valid 2035-01-01 .. 2036-01-01 only (not yet valid: for the trusted-time tests); root_crl_stale.pem has nextUpdate 2020
#   tester_p384       P-384 key (signed by the root with ECDSA/SHA-256), tester_sha384 P-256 key signed with ECDSA/SHA-384
# keyUsage digitalSignature everywhere; extendedKeyUsage 1.3.6.1.4.1.99999.29.100 (tester) / .101 (ECU) - EXAMPLE OIDs,
# replace 99999 with your own Private Enterprise Number. The CRLs are valid for 10 years (nextUpdate): sample only.
# For tests/demos only - the private keys are committed on purpose.
set -e
cd "$(dirname "$0")"
DAYS=3650
TESTER_EKU="extendedKeyUsage=1.3.6.1.4.1.99999.29.100"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n%s\n' "$TESTER_EKU" > "$W/tester.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=1.3.6.1.4.1.99999.29.101\n' > "$W/ecu.ext"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$W/subca.ext"

# issue <name> <ca-prefix> <ca-key-prefix> <ext-file> [sha] [curve]: new key + certificate <name>_cert.pem / <name>_key.pem
issue() {
    openssl ecparam -name ${6:-prime256v1} -genkey -noout -out $1_key.pem
    openssl req -new -key $1_key.pem -subj "/CN=UDS29 Sample $1" -out $W/$1.csr
    openssl x509 -req -in $W/$1.csr -CA $2.pem -CAkey $3.pem -CAserial $W/$2.srl -CAcreateserial \
        -${5:-sha256} -days $DAYS -extfile $4 -out $1_cert.pem
}

openssl ecparam -name prime256v1 -genkey -noout -out root_ca_key.pem
openssl req -x509 -new -key root_ca_key.pem -sha256 -days $DAYS \
    -subj "/CN=UDS29 Sample Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out root_ca.pem

issue tester root_ca root_ca_key "$W/tester.ext"
issue ecu root_ca root_ca_key "$W/ecu.ext"

# tester_<name>: CN, OU, [section] of oem_profile.cnf
for t in "workshop Workshop workshop" "engineering Engineering engineering" "oem OEM oem" "allowlist Allowlist oem"; do
    set -- $t
    openssl ecparam -name prime256v1 -genkey -noout -out tester_$1_key.pem
    openssl req -new -key tester_$1_key.pem -subj "/CN=UDS29 Sample $2 Tester/OU=$3" -out $W/tester_$1.csr
    openssl x509 -req -in $W/tester_$1.csr -CA root_ca.pem -CAkey root_ca_key.pem -CAserial $W/root_ca.srl \
        -sha256 -days $DAYS -extfile oem_profile.cnf -extensions $1 -out tester_$1_cert.pem
done

# validation fixtures
issue tester_p384 root_ca root_ca_key "$W/tester.ext" sha256 secp384r1
issue tester_sha384 root_ca root_ca_key "$W/tester.ext" sha384
issue sub_ca root_ca root_ca_key "$W/subca.ext"
mv sub_ca_cert.pem sub_ca.pem
issue tester_subca sub_ca sub_ca_key "$W/tester.ext"   # sub_ca.pem / sub_ca_key.pem

# CRLs. tester_revoked is issued with `openssl ca` so that it is in the root CA's database, then revoked.
for d in root sub; do mkdir "$W/db_$d"; : > "$W/db_$d/index.txt"; echo 01 > "$W/db_$d/crlnumber"; openssl rand -hex 8 > "$W/db_$d/serial"; done
cat > "$W/ca.cnf" <<EOC
[ca]
default_ca = root
[root]
database = $W/db_root/index.txt
crlnumber = $W/db_root/crlnumber
serial = $W/db_root/serial
new_certs_dir = $W/db_root
certificate = root_ca.pem
private_key = root_ca_key.pem
default_md = sha256
default_crl_days = $DAYS
policy = any
unique_subject = no
[sub]
database = $W/db_sub/index.txt
crlnumber = $W/db_sub/crlnumber
serial = $W/db_sub/serial
new_certs_dir = $W/db_sub
certificate = sub_ca.pem
private_key = sub_ca_key.pem
default_md = sha256
default_crl_days = $DAYS
policy = any
unique_subject = no
[any]
commonName = supplied
EOC
openssl ecparam -name prime256v1 -genkey -noout -out tester_revoked_key.pem
openssl req -new -key tester_revoked_key.pem -subj "/CN=UDS29 Sample tester_revoked" -out "$W/tester_revoked.csr"
openssl ca -batch -config "$W/ca.cnf" -name root -in "$W/tester_revoked.csr" -days $DAYS -notext \
    -extfile "$W/tester.ext" -out tester_revoked_cert.pem 2>/dev/null
openssl ca -batch -config "$W/ca.cnf" -name root -revoke tester_revoked_cert.pem -crl_reason keyCompromise 2>/dev/null
openssl ca -batch -config "$W/ca.cnf" -name root -gencrl -out root_crl.pem 2>/dev/null
openssl ca -batch -config "$W/ca.cnf" -name sub -gencrl -out sub_ca_crl.pem 2>/dev/null

# not-yet-valid tester (trusted time hook / skip tests) and a CRL that is long out of date
openssl ecparam -name prime256v1 -genkey -noout -out tester_future_key.pem
openssl req -new -key tester_future_key.pem -subj "/CN=UDS29 Sample tester_future" -out "$W/tester_future.csr"
openssl ca -batch -config "$W/ca.cnf" -name root -in "$W/tester_future.csr" -notext -startdate 20350101000000Z \
    -enddate 20360101000000Z -extfile "$W/tester.ext" -out tester_future_cert.pem 2>/dev/null
openssl ca -batch -config "$W/ca.cnf" -name root -gencrl -crl_lastupdate 20200101000000Z -crl_nextupdate 20200201000000Z \
    -out root_crl_stale.pem 2>/dev/null
