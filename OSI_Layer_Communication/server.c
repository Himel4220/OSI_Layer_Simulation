/*
 * server.c - listens on a TCP socket, decapsulates the incoming frame through
 * all 7 layers (L1 -> L7), then encapsulates an ACK (L7 -> L1) and sends it back.
 *
 *   ./server [--port N] [--bind ADDR] [--once] [--machine]
 *
 *   --port 0   let the kernel pick a free port (printed in the LISTENING event)
 *   --once     serve a single connection and exit
 *   --machine  tab-separated trace lines for osi_ui.py
 */
#define _GNU_SOURCE
#include "layers.h"
#include "net.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(const char *p)
{
    fprintf(stderr, "usage: %s [--port N] [--bind ADDR] [--once] [--machine]\n", p);
}

static void fill_addr(const struct sockaddr_in *sa, char *ip, size_t ipcap,
                      uint16_t *port)
{
    inet_ntop(AF_INET, &sa->sin_addr, ip, (socklen_t)ipcap);
    *port = ntohs(sa->sin_port);
}

static int serve(int conn, const struct sockaddr_in *peer)
{
    stack_ctx_t ctx;
    struct sockaddr_in local;
    socklen_t ll = sizeof local;
    buf_t wire;
    char msg[MAX_APP + 1], reply[MAX_APP + 1];

    memset(&ctx, 0, sizeof ctx);
    getsockname(conn, (struct sockaddr *)&local, &ll);
    fill_addr(&local, ctx.local_ip, sizeof ctx.local_ip, &ctx.local_port);
    fill_addr(peer, ctx.remote_ip, sizeof ctx.remote_ip, &ctx.remote_port);
    snprintf(ctx.local_mac, sizeof ctx.local_mac, "02:00:00:00:00:02");
    snprintf(ctx.remote_mac, sizeof ctx.remote_mac, "02:00:00:00:00:01");

    emit_event("server", "ACCEPTED", "local=%s:%u;remote=%s:%u", ctx.local_ip,
               (unsigned)ctx.local_port, ctx.remote_ip, (unsigned)ctx.remote_port);

    if (recv_frame(conn, &wire) < 0) {
        emit_event("server", "ERROR", "reason=connection closed before a frame arrived");
        return -1;
    }
    emit_event("server", "WIRE_RX", "bytes=%zu", wire.len);

    int rc = stack_recv(&ctx, "server", &wire, msg, sizeof msg);
    if (rc < 0) {
        emit_event("server", "ERROR", "layer=%d;reason=%s", -rc, stack_error());
        return -1;                        /* closing the socket = no reply */
    }
    emit_deliver("server", ctx.app_type, msg);

    /* The server application: acknowledge and shout the message back. */
    size_t n = strlen(msg);
    int off = snprintf(reply, sizeof reply, "ACK: %zu bytes -> ", n);
    for (size_t i = 0; i < n && (size_t)off + 1 < sizeof reply; i++)
        reply[off++] = (char)toupper((unsigned char)msg[i]);
    reply[off] = '\0';

    rc = stack_send(&ctx, "server", "ACK", reply, &wire);
    if (rc < 0) {
        emit_event("server", "ERROR", "layer=%d;reason=%s", -rc, stack_error());
        return -1;
    }
    if (send_frame(conn, &wire) < 0) {
        emit_event("server", "ERROR", "reason=send failed");
        return -1;
    }
    emit_event("server", "WIRE_TX", "bytes=%zu", wire.len);
    return 0;
}

int main(int argc, char **argv)
{
    int port = 5050, once = 0, machine = 0;
    const char *bind_addr = "127.0.0.1";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind_addr = argv[++i];
        else if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "--machine")) machine = 1;
        else { usage(argv[0]); return 2; }
    }
    trace_set_mode(machine ? TRACE_MACHINE : TRACE_PRETTY);
    signal(SIGPIPE, SIG_IGN);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1) {
        emit_event("server", "ERROR", "reason=bad bind address %s", bind_addr);
        return 2;
    }
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(ls, 4) < 0) {
        emit_event("server", "ERROR", "reason=bind/listen failed: %s", strerror(errno));
        return 1;
    }
    socklen_t sl = sizeof sa;
    getsockname(ls, (struct sockaddr *)&sa, &sl);
    emit_event("server", "LISTENING", "addr=%s;port=%u", bind_addr,
               (unsigned)ntohs(sa.sin_port));

    int status = 0;
    for (;;) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        int conn = accept(ls, (struct sockaddr *)&peer, &pl);
        if (conn < 0) continue;
        if (serve(conn, &peer) < 0) status = 1;
        close(conn);
        if (once) break;
    }
    close(ls);
    return status;
}
