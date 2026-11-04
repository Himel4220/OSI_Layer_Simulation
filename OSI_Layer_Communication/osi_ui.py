#!/usr/bin/env python3
"""
osi_ui.py - user application and visualiser for the OSI simulation.

It starts the C `server`, then the C `client`, and reads the trace lines both
programs print.  The data path is drawn as a zig-zag:

    client  L7 -> L1  (encapsulation)   --wire-->   server  L1 -> L7  (decapsulation)
    server  L7 -> L1  (encapsulation)   --wire-->   client  L1 -> L7  (decapsulation)

Progress is printed as a checkpoint after every two layers, followed by a
summary of how much each layer added to the PDU.

    python3 osi_ui.py                     # interactive prompt
    python3 osi_ui.py -m "Hello OSI"      # one message
    python3 osi_ui.py -m "x" --step       # press Enter at every checkpoint
    python3 osi_ui.py -m "x" --corrupt    # flip a bit on the wire and watch L2 drop it
"""
import argparse
import os
import re
import select
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "client")
SERVER = os.path.join(HERE, "server")
MAX_MSG = 200


class SimError(Exception):
    pass


class FrameDropped(Exception):
    def __init__(self, host, layer, reason):
        super().__init__(reason)
        self.host, self.layer, self.reason = host, layer, reason


# --------------------------------------------------------------- plumbing ---

class Stream:
    """Line reader on a child's stdout with a timeout (no threads needed)."""

    def __init__(self, proc, name):
        self.proc, self.name = proc, name
        self.fd = proc.stdout.fileno()
        self.buf = b""
        self.noise = []

    def _line(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise SimError(f"timed out waiting for the {self.name}")
            ready, _, _ = select.select([self.fd], [], [], left)
            if not ready:
                continue
            chunk = os.read(self.fd, 65536)
            if not chunk:
                rest, self.buf = self.buf, b""
                return rest.decode("utf-8", "replace") if rest else None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace")

    def event(self, timeout):
        while True:
            line = self._line(timeout)
            if line is None:
                extra = f": {' | '.join(self.noise)}" if self.noise else ""
                raise SimError(f"the {self.name} exited unexpectedly{extra}")
            if line.startswith("TRACE\t"):
                p = line.split("\t", 7)
                if len(p) == 8:
                    return {"type": "TRACE", "host": p[1], "dir": p[2],
                            "layer": int(p[3]), "name": p[4], "pdu": p[5],
                            "len": int(p[6]), "data": p[7]}
            elif line.startswith("EVENT\t"):
                p = line.split("\t", 3)
                if len(p) == 4:
                    return {"type": "EVENT", "host": p[1], "kind": p[2], "detail": p[3]}
            self.noise.append(line)


def kv(detail):
    out = {}
    for part in detail.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def unescape(s):
    raw = re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), s)
    return raw.encode("latin-1").decode("utf-8", "replace")


# ----------------------------------------------------------------- output ---

class Ui:
    BAR = 28

    def __init__(self, args):
        self.a = args
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        c = (lambda n: f"\033[{n}m") if color else (lambda n: "")
        self.reset, self.bold, self.dim = c(0), c(1), c(2)
        self.cli, self.srv, self.wire = c(36), c(35), c(33)
        self.ok, self.bad = c(32), c(31)
        self.width = max(78, min(shutil.get_terminal_size((100, 24)).columns, 140))
        self.interactive = sys.stdin.isatty()

    def p(self, s=""):
        print(s, flush=True)

    def col(self, host):
        return self.cli if host == "client" else self.srv

    def pause(self):
        if self.a.step and self.interactive:
            input(f"{self.dim}    press Enter for the next checkpoint...{self.reset}")
        elif self.a.delay > 0:
            time.sleep(self.a.delay)

    def banner(self, msg, port):
        w = self.width
        self.p()
        self.p(f"{self.bold}{'=' * w}{self.reset}")
        self.p(f"{self.bold} OSI 7-layer simulation{self.reset}   "
               f"client {self.cli}127.0.0.1{self.reset} -> server {self.srv}127.0.0.1:{port}{self.reset}")
        self.p(f" message: {self.bold}{msg!r}{self.reset} ({len(msg.encode())} bytes)")
        self.p(f"{self.bold}{'=' * w}{self.reset}")

    def pass_title(self, host, direction, n):
        c = self.col(host)
        verb = ("encapsulation  L7 -> L1" if direction == "TX"
                else "decapsulation  L1 -> L7")
        self.p()
        self.p(f"{c}{self.bold}pass {n} of 4  \u00b7  {host.upper()} {direction}  -  {verb}{self.reset}")

    def clip(self, ev, room):
        d = ev["data"]
        room = max(room, 12)
        if ev["layer"] == 1:                     # show the signal byte by byte
            d = " ".join([d[i:i + 8] for i in range(0, len(d), 8)][: room // 9 + 1])
        return d if len(d) <= room else d[: room - 1] + "\u2026"

    def checkpoint(self, host, direction, group, n, nck, done):
        c = self.col(host)
        arrow = "\u25bc" if direction == "TX" else "\u25b2"
        lo, hi = group[0]["layer"], group[-1]["layer"]
        span = f"L{lo}" if lo == hi else f"L{lo}\u2192L{hi}"
        title = f" checkpoint {n}/{nck} \u00b7 {host} {direction} \u00b7 {span} "
        rule = "\u2500" * (self.width - len(title) - 3)
        self.p(f"{c}\u250c\u2500{title}{rule}{self.reset}")
        for ev in group:
            indent = "  " * (7 - ev["layer"])          # the zig-zag staircase
            unit = "bits" if ev["layer"] == 1 else "B"
            head = f"{arrow} L{ev['layer']} {ev['name']:<12} {ev['pdu']:<7}{ev['len']:>5} {unit:<4} "
            room = self.width - 4 - len(indent) - len(head)
            self.p(f"{c}\u2502{self.reset} {indent}{self.bold}{head}{self.reset}{self.clip(ev, room)}")
        filled = round(done / 7 * self.BAR)
        bar = "\u2588" * filled + "\u2591" * (self.BAR - filled)
        self.p(f"{c}\u2514\u2500 progress {bar} {done}/7 layers{self.reset}")

    def info(self, ev, port=None):
        kind, d, host = ev["kind"], kv(ev["detail"]), ev["host"]
        c = self.col(host)
        if kind == "CONNECTED":
            self.p(f"  {c}client connected  {d['local']} \u2192 {d['remote']}{self.reset}")
        elif kind == "ACCEPTED":
            self.p(f"  {c}server accepted   {d['remote']} \u2192 {d['local']}{self.reset}")
        elif kind == "WIRE_RX":
            self.p(f"  {self.wire}\u25c0 {host} read {d['bytes']} bits from the socket{self.reset}")
        elif kind == "CORRUPT":
            self.p(f"  {self.bad}\u26a0 --corrupt: bit {d['bit']} flipped in flight{self.reset}")
        elif kind == "WIRE_TX":
            arrow = "\u25b6" if host == "client" else "\u25c0"
            side = "client \u2192 server" if host == "client" else "server \u2192 client"
            txt = f" {d['bytes']} bits on the wire ({side}) "
            fill = self.width - len(txt) - 4
            line = "\u2550" * (fill // 2) + txt + "\u2550" * (fill - fill // 2)
            self.p(f"{self.wire}{self.bold}  {line}{arrow}{self.reset}")
        elif kind == "DELIVER":
            typ, _, msg = ev["detail"].partition(";msg=")
            self.p(f"  {self.ok}{self.bold}\u2714 {host} application received "
                   f"[{typ.split('=')[1]}]: {unescape(msg)!r}{self.reset}")

    def dropped(self, e):
        self.p()
        self.p(f"{self.bad}{self.bold}\u2718 {e.host} dropped the PDU at layer L{e.layer}: {e.reason}{self.reset}")
        self.p(f"{self.dim}  Nothing above L{e.layer} ever saw the corrupted data - each layer "
               f"validates its own header before passing the payload up.{self.reset}")

    def summary(self, req, rsp, sent, got_reply):
        self.p()
        self.p(f"{self.bold}Encapsulation overhead per layer{self.reset}  "
               f"{self.dim}(+N = what that layer added){self.reset}")
        self.p(f"  {'layer':<17}{'PDU':<9}{'request':>14}{'':>8}{'reply':>14}{'':>8}")
        prev_q, prev_r = len(sent.encode()), len(got_reply.encode())
        for L in range(7, 0, -1):
            q, r = req[L]["len"], rsp[L]["len"]
            unit = "bit" if L == 1 else "B"
            self.p(f"  L{L} {req[L]['name']:<14}{req[L]['pdu']:<9}"
                   f"{q:>10} {unit:<3}{'+' + str(q - prev_q):>8}"
                   f"{r:>10} {unit:<3}{'+' + str(r - prev_r):>8}")
            prev_q, prev_r = q, r
        n = max(len(sent.encode()), 1)
        self.p(f"{self.dim}  {n} B of user data -> {req[2]['len']} B frame -> {req[1]['len']} bits on the wire "
               f"({req[1]['len'] / 8 / n:.1f}x the original size){self.reset}")
        self.p("=" * self.width)


# ------------------------------------------------------------- simulation ---

def run_pass(ui, stream, host, direction, stop, number, timeout):
    ui.pass_title(host, direction, number)
    last_layer = 1 if direction == "TX" else 7
    group, traces, done, n = [], [], 0, 0

    def flush():
        nonlocal group, done, n
        if not group:
            return
        n += 1
        done += len(group)
        ui.checkpoint(host, direction, group, n, 4, done)
        group = []
        ui.pause()

    while True:
        ev = stream.event(timeout)
        if ev["type"] == "TRACE":
            group.append(ev)
            traces.append(ev)
            if len(group) == 2 or ev["layer"] == last_layer:
                flush()
            continue
        flush()
        if ev["kind"] == "ERROR":
            d = ev["detail"]
            reason = d.partition(";reason=")[2] or d.partition("reason=")[2]
            if d.startswith("layer="):
                reason = re.sub(r"^L\d: ", "", reason)      # layer is shown separately
                raise FrameDropped(ev["host"], int(kv(d)["layer"]), reason)
            raise SimError(f"{ev['host']}: {reason}")
        ui.info(ev)
        if ev["kind"] == stop:
            return traces, ev


def simulate(ui, msg):
    procs = []
    try:
        server = subprocess.Popen([SERVER, "--machine", "--once", "--port", "0"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        procs.append(server)
        sv = Stream(server, "server")
        ev = sv.event(ui.a.timeout)
        if ev["type"] != "EVENT" or ev["kind"] != "LISTENING":
            raise SimError(f"server did not start: {ev}")
        port = kv(ev["detail"])["port"]

        cmd = [CLIENT, "--machine", "--port", port]
        if ui.a.corrupt:
            cmd.append("--corrupt")
        client = subprocess.Popen(cmd + ["--", msg], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, bufsize=0)
        procs.append(client)
        cl = Stream(client, "client")

        ui.banner(msg, port)
        t = ui.a.timeout
        req, _ = run_pass(ui, cl, "client", "TX", "WIRE_TX", 1, t)
        _, ev = run_pass(ui, sv, "server", "RX", "DELIVER", 2, t)
        got = unescape(ev["detail"].partition(";msg=")[2])
        rsp, _ = run_pass(ui, sv, "server", "TX", "WIRE_TX", 3, t)
        _, ev = run_pass(ui, cl, "client", "RX", "DELIVER", 4, t)
        reply = unescape(ev["detail"].partition(";msg=")[2])

        ui.p()
        if got == msg:
            ui.p(f"{ui.ok}{ui.bold}\u2714 server received the message intact{ui.reset}")
        else:
            ui.p(f"{ui.bad}{ui.bold}\u2718 message changed in transit: {got!r}{ui.reset}")
        ui.summary({e["layer"]: e for e in req}, {e["layer"]: e for e in rsp}, msg, reply)
        return True
    except FrameDropped as e:
        ui.dropped(e)
        ui.p("=" * ui.width)
        return False
    except SimError as e:
        ui.p(f"{ui.bad}error: {e}{ui.reset}")
        return False
    finally:
        for pr in procs:
            try:
                pr.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pr.kill()
            if pr.stdout:
                pr.stdout.close()


def ensure_built():
    if os.access(CLIENT, os.X_OK) and os.access(SERVER, os.X_OK):
        return
    print("building the C programs (make)...", flush=True)
    r = subprocess.run(["make", "-C", HERE], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(r.stdout + r.stderr)


def main():
    ap = argparse.ArgumentParser(description="OSI 7-layer simulation visualiser")
    ap.add_argument("-m", "--message", help="message to send (omit for an interactive prompt)")
    ap.add_argument("--delay", type=float, default=None,
                    help="seconds between checkpoints (default 0.8 on a terminal, 0 otherwise)")
    ap.add_argument("--step", action="store_true", help="wait for Enter at every checkpoint")
    ap.add_argument("--corrupt", action="store_true",
                    help="flip one bit on the wire to show the Data Link layer rejecting it")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    if args.delay is None:
        args.delay = 0.8 if sys.stdout.isatty() else 0.0

    ensure_built()
    ui = Ui(args)

    def send(text):
        if not text:
            return True
        if len(text.encode()) > MAX_MSG:
            print(f"message too long ({len(text.encode())} > {MAX_MSG} bytes)")
            return False
        return simulate(ui, text)

    if args.message is not None:
        sys.exit(0 if send(args.message) else 1)

    print("OSI simulation - type a message (empty line or Ctrl-D to quit)")
    try:
        while True:
            text = input("message> ").strip()
            if not text:
                break
            send(text)
    except (EOFError, KeyboardInterrupt):
        print()


if __name__ == "__main__":
    main()
