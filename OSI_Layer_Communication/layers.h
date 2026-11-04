#ifndef LAYERS_H
#define LAYERS_H

#include <stddef.h>
#include <stdint.h>

#define MAX_BUF 16384   /* biggest PDU / wire buffer (bits are 1 char each)   */
#define MAX_MSG 200     /* biggest message the user may type                  */
#define MAX_APP 512     /* biggest decoded application text (reply included)  */

enum { TRACE_PRETTY = 0, TRACE_MACHINE = 1 };

typedef struct {
    char   data[MAX_BUF];
    size_t len;
} buf_t;

/* Per-endpoint state shared by all layers (addresses, session, counters). */
typedef struct {
    char     local_ip[16],  remote_ip[16];
    char     local_mac[18], remote_mac[18];
    uint16_t local_port,    remote_port;
    uint32_t session_id;    /* L5: 0 until a session is opened/adopted      */
    uint32_t seq;           /* L5: messages sent in this session            */
    uint32_t peer_seq;      /* L5: last sequence number seen from the peer  */
    uint32_t tx_bytes;      /* L4: byte-stream offset of the next segment   */
    char     app_type[8];   /* L7: "MSG" / "ACK" (last sent or received)    */
} stack_ctx_t;

/* Output mode: human readable lines, or tab-separated lines for osi_ui.py. */
void trace_set_mode(int mode);
void emit_event(const char *host, const char *kind, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void emit_deliver(const char *host, const char *type, const char *msg);

/* Encapsulate L7 -> L1.  Returns 0, or -N if layer N failed.               */
int stack_send(stack_ctx_t *c, const char *host, const char *type,
               const char *msg, buf_t *wire);

/* Decapsulate L1 -> L7.  Returns 0, or -N if layer N rejected the PDU.     */
int stack_recv(stack_ctx_t *c, const char *host, const buf_t *wire,
               char *msg, size_t cap);

const char *stack_error(void);   /* reason for the last failure */

#endif
