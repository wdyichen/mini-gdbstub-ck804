#include "conn.h"
#ifdef __MINGW32__
#include <windows.h>
#else
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "utils/csum.h"
#include "utils/log.h"

#ifdef __MINGW32__
#if !defined(POLLIN)
#define POLLIN     0x1
#endif
#if !defined(POLLOUT)
#define POLLOUT    0x2
#endif
#endif //__MINGW32__

static bool socket_poll(int socket_fd, int timeout, int events)
{
#ifdef __MINGW32__
#if 1
    fd_set sockets_set;
    struct timeval t;
    struct timeval *tm;
    int result = -1;

    FD_ZERO(&sockets_set);
	FD_SET(socket_fd, &sockets_set);

	if (timeout > 0)
	{
	    t.tv_sec  = timeout / 1000;
        t.tv_usec = (timeout % 1000) * 1000;
        tm = &t;
    }
    else if (timeout == 0)
	{
	    t.tv_sec  = 0;
        t.tv_usec = 0;
        tm = &t;
    }
    else
    {
        tm = NULL;
    }

    if (POLLIN == events)
        result = select(socket_fd + 1, &sockets_set, NULL, NULL, tm);
    else if (POLLOUT == events)
        result = select(socket_fd + 1, NULL, &sockets_set, NULL, tm);
    else
        return false;

    if (result > 0)
    {
        if (FD_ISSET(socket_fd, &sockets_set))
            return true;
    }

    return false;
#else
    (void)socket_fd;
    (void)timeout;
    (void)events;

    return true;
#endif
#else //__MINGW32__
    struct pollfd pfd = (struct pollfd){
        .fd = socket_fd,
        .events = events,
    };

    return (poll(&pfd, 1, timeout) > 0) && (pfd.revents & events);
#endif
}

static bool socket_readable(int socket_fd, int timeout)
{
    return socket_poll(socket_fd, timeout, POLLIN);
}

static bool socket_writable(int socket_fd, int timeout)
{
    return socket_poll(socket_fd, timeout, POLLOUT);
}

bool conn_init(conn_t *conn, char *addr_str, int port)
{
#ifdef __MINGW32__
    WSADATA wsaData;
    WORD wVersionRequested;

    wVersionRequested = MAKEWORD(1, 1);
    WSAStartup(wVersionRequested, &wsaData);
#endif

    if(!pktbuf_init(&conn->pktbuf))
        return false;

    conn->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->listen_fd < 0)
        return false;

    int optval = 1;
#ifdef __MINGW32__
    if (setsockopt(conn->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval)) < 0) {
#else
    if (setsockopt(conn->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
#endif
        warn("Set sockopt fail.\n");
        goto fail;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(addr_str);
    addr.sin_port = htons(port);
    if (bind(conn->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        warn("Bind fail.\n");
        goto fail;
    }

    if (listen(conn->listen_fd, 1) < 0) {
        warn("Listen fail.\n");
        goto fail;
    }

    conn->socket_fd = accept(conn->listen_fd, NULL, NULL);
    if (conn->socket_fd < 0) {
        warn("Accept fail.\n");
        goto fail;
    }

    return true;

fail:
    close(conn->listen_fd);
    return false;
}

void conn_recv_packet(conn_t *conn)
{
    while (!pktbuf_is_complete(&conn->pktbuf) &&
           socket_readable(conn->socket_fd, -1)) {
        int nread = pktbuf_fill_from_file(&conn->pktbuf, conn->socket_fd);
        if (nread == -1)
            break;
    }

    conn_send_str(conn, STR_ACK);
}

packet_t *conn_pop_packet(conn_t *conn)
{
    packet_t *pkt = pktbuf_pop_packet(&conn->pktbuf);

    return pkt;
}

bool conn_try_recv_intr(conn_t *conn)
{
    char ch;

    if (!socket_readable(conn->socket_fd, 0))
        return false;

    int nread = recv(conn->socket_fd, &ch, 1, 0);
    if (nread != 1)
        return false;

    /* FIXME: The character must be INTR_CHAR, otherwise the library
     * may work incorrectly. However, I'm not sure if this implementation
     * can always meet our expectation (concurrent is so hard QAQ). */
    assert(ch == INTR_CHAR);
    return true;
}

void conn_send_str(conn_t *conn, char *str)
{
    uint32_t len = strlen(str);

    while (len > 0 && socket_writable(conn->socket_fd, -1)) {
        int nwrite = send(conn->socket_fd, str, len, 0);
        if (nwrite == -1)
            break;
        len -= nwrite;
    }
}

void conn_send_pktstr(conn_t *conn, char *pktstr)
{
    char packet[MAX_SEND_PACKET_SIZE + 1];
    uint32_t len = strlen(pktstr);

    /* 2: '$' + '#'
     * 2: checksum digits(maximum)
     * 1: '\0' */
    assert(len + 2 + CSUM_SIZE + 1 <= sizeof(packet));

    packet[0] = '$';
    memcpy(packet + 1, pktstr, len);
    packet[len + 1] = '#';

    char csum_str[4];
    uint8_t csum = compute_checksum(pktstr, len);
    uint32_t csum_len = snprintf(csum_str, sizeof(csum_str) - 1, "%02x", csum);
    assert(csum_len == CSUM_SIZE);
    memcpy(packet + len + 2, csum_str, csum_len);
    packet[len + 2 + csum_len] = '\0';

#ifdef DEBUG
    printf("send packet = %s,", packet);
    printf(" checksum = %d\n", csum);
    printf(" packet size = %u\n", (uint32_t)strlen(packet));
#endif
    conn_send_str(conn, packet);
}

void conn_close(conn_t *conn)
{
    close(conn->socket_fd);
    close(conn->listen_fd);
    pktbuf_destroy(&conn->pktbuf);

#ifdef __MINGW32__
    WSACleanup();
#endif
}
