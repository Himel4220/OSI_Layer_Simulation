/*
 * client.c - encapsulates a message through all 7 layers (L7 -> L1), sends the
 * resulting bit stream over a TCP socket, then decapsulates the server's reply.
 *
 *   ./client [--host IP] [--port N] [--machine] [--corrupt] [--] "message"
 *
 *   --corrupt  flip one bit on the wire (the server's Data Link layer should
 *              catch it with the FCS check)
 */
#define _GNU_SOURCE
#include "layers.h"
#include "net.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *p)
{
    fprintf(stderr,
            "usage: %s [--host IP] [--port N] [--machine] [--corrupt] [--] \"message\"\n", p);
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *msg = NULL;
    int port = 5050, machine = 0, corrupt = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { if (i + 1 < argc) msg = argv[i + 1]; break; }
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--machine")) machine = 1;
        else if (!strcmp(argv[i], "--corrupt")) corrupt = 1;
        else if (argv[i][0] == '-' && argv[i][1] == '-') { usage(argv[0]); return 2; }
        else msg = argv[i];
    }
    if (!msg) { usage(argv[0]); return 2; }
    trace_set_mode(machine ? TRACE_MACHINE : TRACE_PRETTY);

    if (strlen(msg) > MAX_MSG) {
        emit_event("client", "ERROR", "reason=message longer than %d bytes", MAX_MSG);
        return 2;
    }
    if (!strcmp(host, "localhost")) host = "127.0.0.1";

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        emit_event("client", "ERROR", "reason=bad IPv4 address %s", host);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        emit_event("client", "ERROR", "reason=cannot connect to %s:%d", host, port);
        return 1;
    }

    stack_ctx_t ctx;
    struct sockaddr_in local;
    socklen_t ll = sizeof local;
    memset(&ctx, 0, sizeof ctx);
    getsockname(fd, (struct sockaddr *)&local, &ll);
    inet_ntop(AF_INET, &local.sin_addr, ctx.local_ip, sizeof ctx.local_ip);
    inet_ntop(AF_INET, &sa.sin_addr, ctx.remote_ip, sizeof ctx.remote_ip);
    ctx.local_port = ntohs(local.sin_port);
    ctx.remote_port = (uint16_t)port;
    snprintf(ctx.local_mac, sizeof ctx.local_mac, "02:00:00:00:00:01");
    snprintf(ctx.remote_mac, sizeof ctx.remote_mac, "02:00:00:00:00:02");
    ctx.session_id = ((uint32_t)time(NULL) * 2654435761u ^ (uint32_t)getpid()) | 1u;

    emit_event("client", "CONNECTED", "local=%s:%u;remote=%s:%u", ctx.local_ip,
               (unsigned)ctx.local_port, ctx.remote_ip, (unsigned)ctx.remote_port);

    /* ---- transmit: L7 -> L1 ---- */
    buf_t wire;
    int rc = stack_send(&ctx, "client", "MSG", msg, &wire);
    if (rc < 0) {
        emit_event("client", "ERROR", "layer=%d;reason=%s", -rc, stack_error());
        return 1;
    }
    if (corrupt) {
        size_t bit = wire.len / 2;
        wire.data[bit] = wire.data[bit] == '0' ? '1' : '0';
        emit_event("client", "CORRUPT", "bit=%zu", bit);
    }
    if (send_frame(fd, &wire) < 0) {
        emit_event("client", "ERROR", "reason=send failed");
        return 1;
    }
    emit_event("client", "WIRE_TX", "bytes=%zu", wire.len);

    /* ---- receive the reply: L1 -> L7 ---- */
    if (recv_frame(fd, &wire) < 0) {
        emit_event("client", "ERROR", "reason=server closed the connection without a reply");
        return 1;
    }
    emit_event("client", "WIRE_RX", "bytes=%zu", wire.len);

    char reply[MAX_APP + 1];
    rc = stack_recv(&ctx, "client", &wire, reply, sizeof reply);
    if (rc < 0) {
        emit_event("client", "ERROR", "layer=%d;reason=%s", -rc, stack_error());
        return 1;
    }
    emit_deliver("client", ctx.app_type, reply);
    close(fd);
    return 0;
}
