# Transports: DoIP and CAN ISO-TP

libuds29 does not talk to a bus itself: you give the client a function that moves bytes, and you feed the server the
bytes you received. Two complete adapters are included as demos in `examples/transports/`:

| Transport | Files | Runs here |
| --- | --- | --- |
| DoIP, ISO 13400-2:2019 over TCP | `doip.{h,c}`, `doip_server_demo.c`, `doip_client_demo.c` | yes (ctest `doip_demo_uni` / `doip_demo_bi`) |
| CAN ISO-TP, ISO 15765-2, classic CAN | `isotp.{h,c}` (userspace ISO-TP), `can_socketcan.{h,c}` (Linux SocketCAN), `can_loopback.{h,c}` (tests), `can_server_demo.c`, `can_client_demo.c` | ISO-TP over the loopback driver: yes (ctest `IsoTp.*`, `Uds29OverIsoTp.*`). The SocketCAN demos: **not run by the author**, the test machine has no `AF_CAN` in its kernel and no `ip` tool. They compile; CI tries them on `vcan` |

These are demonstration adapters, not part of `libuds29`: no TLS, one tester at a time, no vehicle discovery.

## How a transport plugs in

**Client, blocking.** Register one function with `Uds29_SetTransport(fn, ctx)`:

```c
Std_ReturnType MyTransport(const uint8_t* req, uint16_t len, uint8_t* resp, uint16_t* resp_len, void* ctx);
```

`req` is the full UDS request (SID 0x29 included). Send it, wait for the response, copy it to `resp`, set `*resp_len`
(capacity on entry, length on return) and return `E_OK` if a response arrived. The demos' `Doip_Transport` and
`IsoTpTransport` are the reference.

**Client, non-blocking.** `Uds29_SetTxCallback(fn, ctx)` receives each request; call `Uds29_MainFunction()` cyclically
(it also enforces the P2 timeout) and hand every received response to `Uds29_RxIndication(resp, len)`. Nothing blocks
inside the library, so this is the form for a task that also serves a bus. Start with `Uds29_StartAuthentication(dir)`.
`tests/test_isotp.cpp` drives it over ISO-TP.

**Server (ECU).** Call `Uds29Srv_HandleRequest(req, len, resp, &resp_len)` for every received request with SID 0x29 and
send the `resp` it wrote; call `Uds29Srv_MainFunction()` at least every few hundred milliseconds if you use
`auth_timeout_ms`. For every other service call `Uds29Srv_CheckAccess()` first, see [access-control.md](access-control.md).

One OS lock covers client and server. Two threads of the *same process* where the client uses the *blocking* API
and the server answers from another thread therefore wait for each other until the client's transport times out. A
real tester and ECU are different processes; for an in-process test use the non-blocking client flow, as
`tests/test_isotp.cpp` does.

## DoIP (ISO 13400-2:2019)

`doip.c` implements the generic header (protocol version `0x02`, inverse `0xFD`, payload type, payload length), routing
activation request/response (`0x0005` / `0x0006`), diagnostic message (`0x8001`) with positive acknowledge (`0x8002`)
and negative acknowledge (`0x8003`), and the generic header NACK (`0x0000`). Not implemented: vehicle identification and
announcement (UDP), alive check, entity status, power mode, TLS. Logical addresses are configurable (defaults: tester
`0x0E80`, ECU `0x1000`), TCP port 13400.

The messages are plain ISO 13400-2, so the tester can be pointed at other DoIP entities, for example the
[niketdhale/DOIP_ECU_Simulator](https://github.com/niketdhale/DOIP_ECU_Simulator), with `--host`, `--port`, `--tester`
and `--ecu`. That combination has **not** been tested here; check the addresses and the routing activation type your
simulator expects.

Setup and run, two terminals:

```sh
cmake -S . -B build && cmake --build build -j
# terminal 1: the ECU (loopback only unless you pass --bind)
./build/doip_server_demo --port 13400
# terminal 2: the tester
./build/doip_client_demo --port 13400 --mode bi          # or --mode uni
```

Options: server `--bind IP --port N --tester ADDR --ecu ADDR`, client `--host IP --port N --tester ADDR --ecu ADDR
--mode uni|bi`, both `--pki sample | --ca F --cert F --key F`. The server only accepts routing activation from its
`--tester` address (the answer is code `0x00`, unknown source address).

Output, tester:

```
[client] DoIP routing activated (tester 0x0E80 -> ECU 0x1000)
[client] bidirectional authentication: AUTHENTICATED
[client] deauthentication: OK
PASS
```

Output, ECU:

```
[server] DoIP ECU 0x1000 (tester 0x0E80) listening on 127.0.0.1:13400
[server] tester connected
[server] routing activation from 0x0E80: accepted
[server] state -> CERT_SENT
[server] state -> AUTHENTICATED
[server] state -> IDLE
[server] tester disconnected
```

Both demos are exercised together by `tests/run_doip_demo.sh` (ctest `doip_demo_uni`, `doip_demo_bi`).

## CAN ISO-TP (ISO 15765-2)

`isotp.c` is a small **userspace** ISO-TP: single frame, first frame, consecutive frame and flow control for classic
CAN (8 byte frames), payloads of 1 to 4095 bytes. FlowControl block size and STmin (0x00-0x7F ms, 0xF1-0xF9 =
100-900 us) from the receiver are honoured by the sender; timeouts N_Bs (waiting for FlowControl; at most 16 WAIT frames per block) and N_Cr (waiting for a consecutive frame) are configurable (`IsoTp` struct, default 1000 ms);
`padding` is `-1` (short frames) or a pad byte (default `0xCC`, frames always 8 bytes). It is blocking and single-channel.
Not implemented: CAN FD, extended/mixed addressing, payloads above 4095 bytes.

It talks to a **frame driver**, two functions and a context:

```c
typedef struct {
    int (*send)(uint32_t id, const uint8_t* data, uint8_t dlc, void* ctx);                         /* 0 = ok */
    int (*recv)(uint32_t* id, uint8_t* data, uint8_t* dlc, uint32_t timeout_ms, void* ctx);        /* 1 frame, 0 timeout, <0 error */
    void* ctx;
} IsoTp_CanDriver;
```

Drivers: `can_socketcan.c` (Linux raw SocketCAN, `CAN_RAW` with a receive filter on the rx id; built only on Linux when
`<linux/can.h>` exists) and `can_loopback.c` (two endpoints in one process, used by the tests). A driver for another CAN
stack (Vector XL, PCAN, a microcontroller peripheral) is these two functions.

**Userspace ISO-TP versus the kernel's `can-isotp`.** Linux has an ISO-TP socket type (`CAN_ISOTP`, module `can-isotp`,
`<linux/can/isotp.h>`) that does all of this in the kernel and is the better choice on a Linux tester or gateway when
available. The userspace version exists because it runs anywhere you can write a two-function driver (QNX, other
CAN APIs, bare-metal ports of the same C), is testable without a kernel, and needs no module. It does not use `can-isotp`
and the two interoperate on the wire.

Setup with a virtual CAN interface (Linux with the `vcan` module; not possible in the container this was developed in):

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
cmake -S . -B build && cmake --build build -j
# terminal 1: ECU receives on 0x7E0, answers on 0x7E8
./build/can_server_demo --if vcan0 --tx 0x7E8 --rx 0x7E0
# terminal 2: tester sends on 0x7E0, receives on 0x7E8
./build/can_client_demo --if vcan0 --tx 0x7E0 --rx 0x7E8 --mode bi
# terminal 3 (optional, `apt install can-utils`): watch the frames
candump vcan0
```

Expected, tester:

```
[client] ISO-TP on vcan0: send 0x7E0, receive 0x7E8
[client] bidirectional authentication: AUTHENTICATED
[client] deauthentication: OK
PASS
```

Expected, ECU:

```
[server] ISO-TP on vcan0: receive 0x7E0, answer 0x7E8
[server] state -> CERT_SENT
[server] state -> AUTHENTICATED
[server] state -> IDLE
```

`candump` shows the certificate as a first frame (`7E0 [8] 11 xx 29 02 ...`), the ECU's flow control (`7E8 [8] 30 00 00 CC ...`) and a run of
consecutive frames (`21`, `22`, ... `2F`, `20`, ...). `tests/run_can_demo.sh <server> <client> <uni|bi> [if]` does the
two-process run in one command; the GitHub workflow runs it in a `continue-on-error` job where `vcan` can be loaded.
These SocketCAN steps were not run by the author.

What *is* tested here: `tests/test_isotp.cpp` runs the same ISO-TP code over the in-process loopback bus: all frame
types, lengths 1 to 4095, block size/STmin, padding, N_Bs/N_Cr timeouts, wrong sequence numbers, receive overflow, and a
unidirectional and a bidirectional 0x29 authentication between two threads with the full certificate messages
(several hundred bytes, so multi-frame).

## Writing your own adapter

1. Pick the blocking or the non-blocking client form (above). A server adapter is a loop: receive a message, call
   `Uds29Srv_HandleRequest`, send the answer.
2. The payload is always the UDS message, SID included, at most `UDS29_MAX_MSG_LEN` (1300). Segmentation and addressing
   belong to the transport, not to the library.
3. Handle response pending yourself if your ECU uses it: `7F 29 78` is not produced by this server, but a gateway in between
   may (`IsoTpTransport` in `can_client_demo.c` waits through it).
4. Frame-based buses follow the ISO-TP pattern above: write the two-function driver and reuse `isotp.c`. FlexRay and UART
   have no standard diagnostic transport in this repo: for FlexRay use the ISO 10681 (FlexRay TP) of your stack and put
   `Uds29Srv_HandleRequest` behind it; over a UART frame the message yourself (length prefix plus checksum) and run the
   same loop. Both are only a place to call the two functions; neither was tried here.
