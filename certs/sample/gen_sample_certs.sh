#!/bin/sh
# Generates the SAMPLE PKI (EC P-256, 10y): root CA, tester and ECU cert+key.
# For tests/demos only - the private keys are committed on purpose.
set -e
cd "$(dirname "$0")"
DAYS=3650
EXT=$(mktemp)
trap 'rm -f "$EXT"' EXIT
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' > "$EXT"

openssl ecparam -name prime256v1 -genkey -noout -out root_ca_key.pem
openssl req -x509 -new -key root_ca_key.pem -sha256 -days $DAYS \
    -subj "/CN=UDS29 Sample Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out root_ca.pem

for who in tester ecu; do
    openssl ecparam -name prime256v1 -genkey -noout -out ${who}_key.pem
    openssl req -new -key ${who}_key.pem -subj "/CN=UDS29 Sample $who" -out $who.csr
    openssl x509 -req -in $who.csr -CA root_ca.pem -CAkey root_ca_key.pem -CAcreateserial \
        -sha256 -days $DAYS -extfile "$EXT" -out ${who}_cert.pem
    rm -f $who.csr
done
rm -f root_ca.srl
