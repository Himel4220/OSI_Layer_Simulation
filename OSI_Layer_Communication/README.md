# OSI 7-layer simulation

A C **client** and **server** that implement all seven OSI layers (encapsulation on
the way down, decapsulation on the way up) and talk over a **real TCP socket**.
A Python **user application** (`osi_ui.py`) launches both, and draws the zig-zag
data flow, printing a checkpoint after every two layers.

```
 client                                              server
 L7 Application   ──┐                            ┌── L7 Application
 L6 Presentation  ──┤                            ├── L6 Presentation
 L5 Session       ──┤   request  (pass 1 → 2)    ├── L5 Session
 L4 Transport     ──┤                            ├── L4 Transport
 L3 Network       ──┤                            ├── L3 Network
 L2 Data Link     ──┤                            ├── L2 Data Link
 L1 Physical      ──┴════ bits over the socket ═══┴── L1 Physical
                      reply    (pass 3 → 4)  ◀ same path in reverse
```

## Build and run

```
make                               # builds ./client and ./server (gcc, no dependencies)
python3 osi_ui.py                  # interactive prompt
python3 osi_ui.py -m "Hello OSI"   # one message
python3 osi_ui.py -m "x" --step    # wait for Enter at every checkpoint
python3 osi_ui.py -m "x" --corrupt # flip a bit on the wire; L2 must reject it
make test                          # both of the above, non-interactive
```

Python 3 and gcc are enough. The C programs also work without the UI:

```
./server --port 5050 &             # --once, --bind ADDR, --machine are also available
./client --port 5050 "Hello OSI"
```

## What each layer does

| Layer | Header added (TX) | Checked on RX |
|---|---|---|
| L7 Application | `APP{type=MSG;len=N}` | header format, length field |
| L6 Presentation | `PRS{enc=hex;xor=5a}`; payload is XOR-ed and hex-encoded | encoding, key, hex digits |
| L5 Session | `SES{sid=…;seq=N}` | session id matches (server adopts it on first message) |
| L4 Transport | `TCP{sp;dp;seq;len;chk}` with Internet checksum | ports, length, checksum |
| L3 Network | `IP{src;dst;ttl;proto;len}` | destination is us, source is the peer, TTL, length |
| L2 Data Link | `MAC{dst;src;type}` + trailer `#FCS=crc32` | CRC-32, destination MAC |
| L1 Physical | 7×`0xAA` preamble + `0xAB` SFD, one `'0'/'1'` char per bit | whole bytes, valid symbols, preamble, SFD |

The server's application acknowledges with `ACK: N bytes -> <MESSAGE IN CAPITALS>`,
sent back through its own full stack, so both directions are exercised.

## How the pieces talk

* `layers.c` is shared by both programs: `stack_send()` runs L7→L1, `stack_recv()` runs L1→L7.
* `net.c` moves a frame over the socket as a 4-byte length plus the bit string.
* With `--machine`, each layer step is printed as a tab-separated `TRACE` line and
  notable moments (`CONNECTED`, `WIRE_TX`, `DELIVER`, `ERROR`, …) as `EVENT` lines.
  `osi_ui.py` reads them from the two child processes in protocol order, so no
  threads or timestamps are needed.

## Limits worth knowing

* The Network, Transport and Data Link headers are **simulated, text-based headers**
  carried inside a normal kernel TCP connection. The kernel does its own real
  L2–L4 work underneath; nothing here uses raw sockets or needs root.
  The real addresses and ports (from `getsockname`) are put into the simulated headers.
* MAC addresses are fixed and made up (`02:00:00:00:00:01` / `…02`); there is no ARP.
* L6 "encryption" is a fixed-key XOR: a demonstration of a presentation-layer
  transformation, not security.
* Physical-layer bits are ASCII characters, so a frame is 8× larger on the socket
  than it would be in binary.
* Messages are limited to 200 bytes; one request and one reply per connection.
* Linux's real stack has no separate session or presentation layers; they are part of
  the application. They are kept here so that all seven layers are visible.
