# Linux guide

Tested here (Ubuntu, GCC, OpenSSL 3.0 and mbedTLS 3.6): everything in this guide. CI runs it on `ubuntu-latest`.

## Prerequisites

- CMake 3.16+, a C11 and C++17 compiler (GCC or Clang), `make` or `ninja`
- OpenSSL development files (default crypto backend): `sudo apt-get install -y libssl-dev` (Fedora: `openssl-devel`)
- Network access on the first configure: GoogleTest is fetched (mbedTLS too with `-DUDS29_CRYPTO=MBEDTLS` and no system mbedTLS 3.x)
- Optional: the `openssl` command line tool (one server test mints a certificate with it and skips itself without; also needed to regenerate `certs/sample`)

## Build

```sh
git clone https://github.com/niketdhale/UDS-29-auth-toolkit.git && cd UDS-29-auth-toolkit
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Useful options (full table in the [README](../README.md#build-options)): `-DUDS29_ROLE=CLIENT|SERVER|BOTH`,
`-DUDS29_CRYPTO=MBEDTLS`, `-DBUILD_SHARED_LIBS=ON`, `-DUDS29_ENABLE_IDSM=ON`.

## Install

```sh
cmake --install build --prefix /opt/uds29
```

Installs `libuds29`, the public headers (`Uds29.h` for CLIENT/BOTH, `Uds29_Server.h` for SERVER/BOTH, plus the shared
`_Types _Cfg _Transport _Codec _Crypto _Os`, and `Uds29_Authz.h` with the server), `uds29_cli`, `uds29Config.cmake` and `uds29.pc`.

## Use in your project

CMake:

```cmake
find_package(uds29 REQUIRED)            # configure with -DCMAKE_PREFIX_PATH=/opt/uds29
target_link_libraries(app PRIVATE uds29::uds29)
```

pkg-config: `cc app.c $(pkg-config --cflags --libs uds29)` (add `--static` for the static library).
`examples/consumer/` is a complete minimal project.

Client (tester) in five lines, blocking API; see `examples/transports/doip_client_demo.c` (DoIP) or `can_client_demo.c` (CAN ISO-TP) for a complete transport:

```c
Uds29_ConfigType cfg = {0x00, 32};
Uds29_Init(&cfg);
Uds29_SetTransport(MyTransport, &conn);
Uds29_PkiConfigType pki = {UDS29_PKI_USER, "ca.pem", "tester.pem", "tester.key", UDS29_PKI_FORMAT_PEM};
if (Uds29_SetPki(&pki) == E_OK && Uds29_AuthenticateBidirectional() == E_OK) { /* authenticated */ }
```

Server (ECU), DCM-style; see `examples/transports/doip_server_demo.c`:

```c
Uds29Srv_ConfigType c = {0};
c.pki = (Uds29_PkiConfigType){UDS29_PKI_USER, "ca.pem", "ecu.pem", "ecu.key", UDS29_PKI_FORMAT_PEM};
c.auth_timeout_ms = 60000;                       /* 0 = off */
Uds29Srv_Init(&c);
/* for every received SID 0x29 request: */
Uds29Srv_HandleRequest(req, req_len, resp, &resp_len);   /* resp_len = capacity in, length out; send resp */
/* cyclically: */ Uds29Srv_MainFunction();
```

Both APIs are thread-safe (one recursive lock shared by client and server). The non-blocking client flow
(`Uds29_StartAuthentication` / `Uds29_MainFunction` / `Uds29_RxIndication`) is shown in `examples/linux_app.c`.

## Run

Client and server share one binary for experiments, the CLI (reads commands or hex from stdin):

```sh
./build/uds29_cli                       # --role client (default): simulated ECU + interactive tester
./build/uds29_cli --role server         # ECU only: hex request lines in, hex response lines out
```

Two-process demo over DoIP (ISO 13400-2, TCP localhost), default port 13400:

```sh
./build/doip_server_demo &                      # sample ECU PKI (certs/sample/ecu_*)
./build/doip_client_demo --mode bi              # or --mode uni; sample tester PKI
kill %1
```

Own PKI instead of the sample one (both programs): `--ca root.pem --cert cert.pem --key key.pem` (PEM).
The CAN ISO-TP variant (`can_server_demo`, `can_client_demo`, needs a SocketCAN interface such as `vcan0`) and the
protocol details are in [transports.md](transports.md); access control from certificates is in
[access-control.md](access-control.md).

## Confirm it works

```sh
ctest --test-dir build
```
```
100% tests passed, 0 tests failed out of 88
```
(the count differs per configuration: 6 for `UDS29_ROLE=CLIENT` or `SERVER`, 92 with IDSM).

```sh
printf '29 08\n29 04\n29 03 00 00 01 AA 00 00\n' | ./build/uds29_cli --role server
```
```
69 08 02
7F 29 12
7F 29 13
```

```sh
./build/doip_server_demo > server.log & sleep 1
./build/doip_client_demo --mode bi
kill %1; cat server.log
```
```
[client] DoIP routing activated (tester 0x0E80 -> ECU 0x1000)
[client] bidirectional authentication: AUTHENTICATED
[client] deauthentication: OK
PASS
--- server.log ---
[server] DoIP ECU 0x1000 (tester 0x0E80) listening on 127.0.0.1:13400
[server] tester connected
[server] routing activation from 0x0E80: accepted
[server] state -> CERT_SENT
[server] state -> AUTHENTICATED
[server] state -> IDLE
[server] tester disconnected
```

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Could NOT find OpenSSL` | install `libssl-dev`, or use `-DUDS29_CRYPTO=MBEDTLS` |
| Configure hangs or fails fetching googletest / mbedTLS | needs network (or a proxy) once; for a cross build use `-DUDS29_BUILD_HOST_TOOLS=OFF` |
| `cannot load ECU PKI` / `FAIL: client init / PKI` | wrong file path, key does not belong to the cert, or the cert does not chain to `--ca`. `UDS29_PKI_SAMPLE` works only from a build tree (it points to `certs/sample`) |
| Client `FAIL` with `nrc=0x52` / `0x54` | server did not accept the client cert (other root CA / not a certificate) |
| Client `FAIL` with `nrc=0x56` | server has `required_roles` set and the client certificate carries none of those roles (see [access-control.md](access-control.md)); `0x55` = the profile could not decode a value in the certificate |
| `connect: Connection refused` | server not running yet or other port; the ctest script waits for the `listening` line |
| `socket(PF_CAN): Address family not supported` | the kernel has no CAN support; load `vcan` / `can_raw` ([transports.md](transports.md)) |
| ctest `doip_demo_*` fails with `bind/listen` | port taken: the script picks `20000 + pid % 20000`; re-run |
| Ed25519 certificates fail with mbedTLS | the mbedTLS backend supports ECDSA P-256 only |
| `error while loading shared libraries: libuds29.so` | `BUILD_SHARED_LIBS=ON`: set `LD_LIBRARY_PATH` to the install `lib` directory |
