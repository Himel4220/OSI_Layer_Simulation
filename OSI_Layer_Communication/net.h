#ifndef NET_H
#define NET_H

#include "layers.h"

/* The "wire": a TCP socket carrying length-prefixed bit strings. */
int send_frame(int fd, const buf_t *b);
int recv_frame(int fd, buf_t *b);

#endif
