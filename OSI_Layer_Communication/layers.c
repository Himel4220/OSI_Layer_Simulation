/*
 * layers.c - the 7-layer stack used by both client and server.
 *
 * Going down (TX) every layer wraps the PDU it receives from above:
 *
 *   L7 Application   APP{type;len}            + message
 *   L6 Presentation  PRS{enc;xor}             + hex(XOR(payload))   (toy "encryption")
 *   L5 Session       SES{sid;seq}             + payload
 *   L4 Transport     TCP{sp;dp;seq;len;chk}   + payload             (Internet checksum)
 *   L3 Network       IP{src;dst;ttl;proto;len}+ payload
 *   L2 Data Link     MAC{dst;src;type}        + payload + #FCS=crc32
 *   L1 Physical      preamble + SFD + frame, one '0'/'1' char per bit
 *
 * Going up (RX) every layer validates and strips its own header, so a
 * corrupted or misaddressed PDU is rejected at the layer that notices it.
 */
#include "layers.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XOR_KEY 0x5A
#define FCS_LEN 13                       /* strlen("#FCS=") + 8 hex digits */

static const char *LAYER_NAME[8] = { "", "Physical", "Data Link", "Network",
                                     "Transport", "Session", "Presentation",
                                     "Application" };
static const char *PDU_NAME[8]   = { "", "Bits", "Frame", "Packet", "Segment",
                                     "Data", "Data", "Data" };
static const char HEXD[] = "0123456789abcdef";

static int  g_mode = TRACE_PRETTY;
static char g_err[200];

void trace_set_mode(int mode) { g_mode = mode; }
const char *stack_error(void) { return g_err; }

static int fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
    return -1;
}

/* ------------------------------------------------------------ output ---- */

/* Printable ASCII stays as is; everything else (and '\') becomes \xNN.     */
static char *escape(const char *s, size_t n)
{
    char *out = malloc(n * 4 + 1);
    size_t o = 0;
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch >= 0x20 && ch < 0x7f && ch != '\\')
            out[o++] = (char)ch;
        else
            o += (size_t)sprintf(out + o, "\\x%02x", ch);
    }
    out[o] = '\0';
    return out;
}

static void trace(const char *host, const char *dir, int layer, const buf_t *b)
{
    char *esc = escape(b->data, b->len);
    if (!esc) return;
    if (g_mode == TRACE_MACHINE)
        printf("TRACE\t%s\t%s\t%d\t%s\t%s\t%zu\t%s\n", host, dir, layer,
               LAYER_NAME[layer], PDU_NAME[layer], b->len, esc);
    else
        printf("[%-6s %s] L%d %-12s %-7s %5zu B  %.72s%s\n", host, dir, layer,
               LAYER_NAME[layer], PDU_NAME[layer], b->len, esc,
               strlen(esc) > 72 ? "..." : "");
    fflush(stdout);
    free(esc);
}

void emit_event(const char *host, const char *kind, const char *fmt, ...)
{
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof detail, fmt, ap);
    va_end(ap);
    for (char *p = detail; *p; p++)               /* keep the line parseable */
        if ((unsigned char)*p < 0x20) *p = '?';
    if (g_mode == TRACE_MACHINE)
        printf("EVENT\t%s\t%s\t%s\n", host, kind, detail);
    else
        printf("[%-6s] %-9s %s\n", host, kind, detail);
    fflush(stdout);
}

void emit_deliver(const char *host, const char *type, const char *msg)
{
    char *esc = escape(msg, strlen(msg));
    if (!esc) return;
    emit_event(host, "DELIVER", "type=%s;msg=%s", type, esc);
    free(esc);
}

/* ----------------------------------------------------------- helpers ---- */

static uint32_t crc32_calc(const char *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= (unsigned char)p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static uint16_t inet_checksum(const char *p, size_t n)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += ((unsigned)(unsigned char)p[i] << 8) | (unsigned char)p[i + 1];
    if (n & 1)
        sum += (unsigned)(unsigned char)p[n - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* out = hdr + in */
static int prepend(buf_t *out, const char *hdr, const buf_t *in)
{
    size_t hl = strlen(hdr);
    if (hl + in->len >= MAX_BUF)
        return fail("PDU too large (%zu bytes)", hl + in->len);
    memcpy(out->data, hdr, hl);
    memcpy(out->data + hl, in->data, in->len);
    out->len = hl + in->len;
    out->data[out->len] = '\0';
    return 0;
}

/* Parse "TAG{body}payload": body -> hdr, payload -> out. */
static int split(const char *d, size_t n, const char *tag,
                 char *hdr, size_t hcap, buf_t *out)
{
    size_t tl = strlen(tag);
    if (n < tl + 2 || memcmp(d, tag, tl) != 0 || d[tl] != '{')
        return -1;
    const char *close = memchr(d + tl + 1, '}', n - tl - 1);
    if (!close) return -1;
    size_t bl = (size_t)(close - (d + tl + 1));
    if (bl >= hcap) return -1;
    memcpy(hdr, d + tl + 1, bl);
    hdr[bl] = '\0';
    size_t pl = n - (size_t)(close - d) - 1;
    memcpy(out->data, close + 1, pl);
    out->len = pl;
    out->data[pl] = '\0';
    return 0;
}

/* Fetch "key=value" from "k1=v1;k2=v2;..." */
static int getfield(const char *hdr, const char *key, char *val, size_t cap)
{
    size_t kl = strlen(key);
    const char *p = hdr;
    while (*p) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            p += kl + 1;
            size_t n = strcspn(p, ";");
            if (n >= cap) return -1;
            memcpy(val, p, n);
            val[n] = '\0';
            return 0;
        }
        p += strcspn(p, ";");
        if (*p == ';') p++;
    }
    return -1;
}

static int getnum(const char *hdr, const char *key, int base, unsigned long *out)
{
    char v[32], *end;
    if (getfield(hdr, key, v, sizeof v) < 0 || !*v) return -1;
    *out = strtoul(v, &end, base);
    return *end ? -1 : 0;
}

/* --------------------------------------------------------- L7 / L6 ------ */

static int tx_app(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[64];
    snprintf(h, sizeof h, "APP{type=%s;len=%zu}", c->app_type, in->len);
    return prepend(out, h, in);
}

static int rx_app(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[64], v[32];
    unsigned long len;
    if (split(in->data, in->len, "APP", h, sizeof h, out) < 0)
        return fail("L7: malformed APP header");
    if (getfield(h, "type", v, sizeof v) < 0 || strlen(v) >= sizeof c->app_type)
        return fail("L7: missing or invalid message type");
    if (getnum(h, "len", 10, &len) < 0 || len != out->len)
        return fail("L7: length field does not match payload");
    strcpy(c->app_type, v);
    return 0;
}

/* Presentation: data representation. Payload is XOR-ed with a fixed key (a
 * stand-in for encryption) and hex-encoded (a stand-in for a wire encoding).*/
static int tx_pres(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    (void)c;
    char h[48];
    snprintf(h, sizeof h, "PRS{enc=hex;xor=%02x}", XOR_KEY);
    size_t hl = strlen(h);
    if (hl + in->len * 2 >= MAX_BUF)
        return fail("L6: payload too large to encode");
    memcpy(out->data, h, hl);
    for (size_t i = 0; i < in->len; i++) {
        unsigned char b = (unsigned char)in->data[i] ^ XOR_KEY;
        out->data[hl + 2 * i]     = HEXD[b >> 4];
        out->data[hl + 2 * i + 1] = HEXD[b & 15];
    }
    out->len = hl + in->len * 2;
    out->data[out->len] = '\0';
    return 0;
}

static int rx_pres(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    (void)c;
    char h[64], v[32];
    unsigned long key;
    if (split(in->data, in->len, "PRS", h, sizeof h, out) < 0)
        return fail("L6: malformed PRS header");
    if (getfield(h, "enc", v, sizeof v) < 0 || strcmp(v, "hex") != 0)
        return fail("L6: unsupported encoding");
    if (getnum(h, "xor", 16, &key) < 0 || key > 0xFF)
        return fail("L6: bad key field");
    if (out->len % 2)
        return fail("L6: odd number of hex digits");
    for (size_t i = 0; i < out->len / 2; i++) {          /* in-place decode */
        int hi = hexval(out->data[2 * i]), lo = hexval(out->data[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return fail("L6: non-hex character in payload");
        out->data[i] = (char)(((hi << 4) | lo) ^ (int)key);
    }
    out->len /= 2;
    out->data[out->len] = '\0';
    return 0;
}

/* --------------------------------------------------------- L5 / L4 ------ */

static int tx_sess(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[64];
    ++c->seq;
    snprintf(h, sizeof h, "SES{sid=%08x;seq=%u}", (unsigned)c->session_id,
             (unsigned)c->seq);
    return prepend(out, h, in);
}

static int rx_sess(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[64];
    unsigned long sid, seq;
    if (split(in->data, in->len, "SES", h, sizeof h, out) < 0)
        return fail("L5: malformed SES header");
    if (getnum(h, "sid", 16, &sid) < 0 || getnum(h, "seq", 10, &seq) < 0)
        return fail("L5: unparsable session fields");
    if (c->session_id == 0)
        c->session_id = (uint32_t)sid;            /* server adopts the session */
    else if (sid != c->session_id)
        return fail("L5: session %08lx does not match active session %08x",
                    sid, (unsigned)c->session_id);
    c->peer_seq = (uint32_t)seq;
    return 0;
}

static int tx_trans(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[96];
    uint16_t chk = inet_checksum(in->data, in->len);
    snprintf(h, sizeof h, "TCP{sp=%u;dp=%u;seq=%u;len=%zu;chk=%04x}",
             (unsigned)c->local_port, (unsigned)c->remote_port,
             (unsigned)c->tx_bytes, in->len, (unsigned)chk);
    c->tx_bytes += (uint32_t)in->len;
    return prepend(out, h, in);
}

static int rx_trans(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[96];
    unsigned long sp, dp, len, chk;
    if (split(in->data, in->len, "TCP", h, sizeof h, out) < 0)
        return fail("L4: malformed TCP header");
    if (getnum(h, "sp", 10, &sp) < 0 || getnum(h, "dp", 10, &dp) < 0 ||
        getnum(h, "len", 10, &len) < 0 || getnum(h, "chk", 16, &chk) < 0)
        return fail("L4: unparsable TCP fields");
    if (dp != c->local_port)
        return fail("L4: segment for port %lu, we listen on %u", dp,
                    (unsigned)c->local_port);
    if (sp != c->remote_port)
        return fail("L4: segment from unexpected port %lu", sp);
    if (len != out->len)
        return fail("L4: length field %lu != payload %zu", len, out->len);
    uint16_t got = inet_checksum(out->data, out->len);
    if (got != chk)
        return fail("L4: checksum mismatch (header %04lx, computed %04x)", chk,
                    (unsigned)got);
    return 0;
}

/* --------------------------------------------------------- L3 / L2 ------ */

static int tx_net(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[128];
    snprintf(h, sizeof h, "IP{src=%s;dst=%s;ttl=64;proto=6;len=%zu}",
             c->local_ip, c->remote_ip, in->len);
    return prepend(out, h, in);
}

static int rx_net(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[128], v[32];
    unsigned long ttl, len;
    if (split(in->data, in->len, "IP", h, sizeof h, out) < 0)
        return fail("L3: malformed IP header");
    if (getfield(h, "dst", v, sizeof v) < 0 || strcmp(v, c->local_ip) != 0)
        return fail("L3: packet addressed to %s, we are %s", v, c->local_ip);
    if (getfield(h, "src", v, sizeof v) < 0 || strcmp(v, c->remote_ip) != 0)
        return fail("L3: unexpected source address %s", v);
    if (getnum(h, "ttl", 10, &ttl) < 0 || ttl == 0)
        return fail("L3: TTL expired");
    if (getnum(h, "len", 10, &len) < 0 || len != out->len)
        return fail("L3: length field does not match payload");
    return 0;
}

static int tx_link(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[128], t[24];
    snprintf(h, sizeof h, "MAC{dst=%s;src=%s;type=0800}", c->remote_mac,
             c->local_mac);
    if (prepend(out, h, in) < 0) return -1;
    if (out->len + FCS_LEN >= MAX_BUF) return fail("L2: frame too large");
    snprintf(t, sizeof t, "#FCS=%08x", (unsigned)crc32_calc(out->data, out->len));
    memcpy(out->data + out->len, t, FCS_LEN);
    out->len += FCS_LEN;
    out->data[out->len] = '\0';
    return 0;
}

static int rx_link(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    char h[128], v[32], hex[9], *end;
    if (in->len < FCS_LEN)
        return fail("L2: runt frame (%zu bytes)", in->len);
    size_t body = in->len - FCS_LEN;
    const char *t = in->data + body;
    if (memcmp(t, "#FCS=", 5) != 0)
        return fail("L2: missing FCS trailer");
    memcpy(hex, t + 5, 8);
    hex[8] = '\0';
    unsigned long want = strtoul(hex, &end, 16);
    uint32_t got = crc32_calc(in->data, body);
    if (*end || want != got)
        return fail("L2: FCS mismatch (frame %s, computed %08x) - frame dropped",
                    hex, (unsigned)got);
    if (split(in->data, body, "MAC", h, sizeof h, out) < 0)
        return fail("L2: malformed MAC header");
    if (getfield(h, "dst", v, sizeof v) < 0 || strcmp(v, c->local_mac) != 0)
        return fail("L2: frame addressed to %s, we are %s", v, c->local_mac);
    return 0;
}

/* --------------------------------------------------------------- L1 ----- */

static int tx_phys(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    (void)c;
    size_t nbytes = 8 + in->len, o = 0;      /* 7 preamble + 1 SFD + frame   */
    if (nbytes * 8 >= MAX_BUF)
        return fail("L1: frame too large for the wire buffer");
    for (size_t i = 0; i < nbytes; i++) {
        unsigned char byte = i < 7 ? 0xAA : i == 7 ? 0xAB
                                               : (unsigned char)in->data[i - 8];
        for (int bit = 7; bit >= 0; bit--)
            out->data[o++] = ((byte >> bit) & 1) ? '1' : '0';
    }
    out->len = o;
    out->data[o] = '\0';
    return 0;
}

static int rx_phys(stack_ctx_t *c, const buf_t *in, buf_t *out)
{
    (void)c;
    if (in->len % 8 != 0)
        return fail("L1: %zu bits is not a whole number of bytes", in->len);
    size_t nb = in->len / 8;
    if (nb < 9)
        return fail("L1: runt signal");
    for (size_t i = 0; i < nb; i++) {
        unsigned v = 0;
        for (int bit = 0; bit < 8; bit++) {
            char ch = in->data[i * 8 + (size_t)bit];
            if (ch != '0' && ch != '1')
                return fail("L1: invalid symbol on the wire");
            v = (v << 1) | (unsigned)(ch - '0');
        }
        out->data[i] = (char)v;
    }
    for (int i = 0; i < 7; i++)
        if ((unsigned char)out->data[i] != 0xAA)
            return fail("L1: bad preamble");
    if ((unsigned char)out->data[7] != 0xAB)
        return fail("L1: start-of-frame delimiter not found");
    memmove(out->data, out->data + 8, nb - 8);
    out->len = nb - 8;
    out->data[out->len] = '\0';
    return 0;
}

/* ------------------------------------------------------------ driver ---- */

typedef int (*layer_fn)(stack_ctx_t *, const buf_t *, buf_t *);

int stack_send(stack_ctx_t *c, const char *host, const char *type,
               const char *msg, buf_t *wire)
{
    static const layer_fn TX[8] = { NULL, tx_phys, tx_link, tx_net, tx_trans,
                                    tx_sess, tx_pres, tx_app };
    buf_t a, b;
    buf_t *cur = &a, *nxt = &b;
    size_t n = strlen(msg);

    if (n > MAX_APP) { fail("message too long"); return -7; }
    memcpy(cur->data, msg, n + 1);
    cur->len = n;
    snprintf(c->app_type, sizeof c->app_type, "%s", type);

    for (int l = 7; l >= 1; l--) {
        if (TX[l](c, cur, nxt) < 0) return -l;
        trace(host, "TX", l, nxt);
        buf_t *t = cur; cur = nxt; nxt = t;
    }
    *wire = *cur;
    return 0;
}

int stack_recv(stack_ctx_t *c, const char *host, const buf_t *wire,
               char *msg, size_t cap)
{
    static const layer_fn RX[8] = { NULL, rx_phys, rx_link, rx_net, rx_trans,
                                    rx_sess, rx_pres, rx_app };
    buf_t a, b;
    buf_t *cur = &a, *nxt = &b;

    *cur = *wire;
    for (int l = 1; l <= 7; l++) {
        trace(host, "RX", l, cur);            /* the PDU as it arrives at L<l> */
        if (RX[l](c, cur, nxt) < 0) return -l;
        buf_t *t = cur; cur = nxt; nxt = t;
    }
    if (cur->len + 1 > cap) { fail("L7: message does not fit"); return -7; }
    memcpy(msg, cur->data, cur->len);
    msg[cur->len] = '\0';
    return 0;
}
