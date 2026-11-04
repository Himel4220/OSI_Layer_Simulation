#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int send_all(int fd, const void *p, size_t n)
{
    const char *s = p;
    while (n) {
        ssize_t r = send(fd, s, n, MSG_NOSIGNAL);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        s += r;
        n -= (size_t)r;
    }
    return 0;
}

static int recv_all(int fd, void *p, size_t n)
{
    char *s = p;
    while (n) {
        ssize_t r = recv(fd, s, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;              /* EOF or error */
        s += r;
        n -= (size_t)r;
    }
    return 0;
}

int send_frame(int fd, const buf_t *b)
{
    uint32_t n = htonl((uint32_t)b->len);
    if (send_all(fd, &n, sizeof n) < 0) return -1;
    return send_all(fd, b->data, b->len);
}

int recv_frame(int fd, buf_t *b)
{
    uint32_t n;
    if (recv_all(fd, &n, sizeof n) < 0) return -1;
    n = ntohl(n);
    if (n == 0 || n >= MAX_BUF) return -1;
    if (recv_all(fd, b->data, n) < 0) return -1;
    b->len = n;
    b->data[n] = '\0';
    return 0;
}
