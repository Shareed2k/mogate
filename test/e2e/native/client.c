#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif
#ifndef POLLWRNORM
#define POLLWRNORM 0x0100
#endif

static int wait_connected(int fd, const char *network) {
    if (strcmp(network, "tcp-select") == 0) {
        fd_set writes;
        FD_ZERO(&writes);
        FD_SET(fd, &writes);
        struct timeval timeout = {.tv_sec = 5};
        return select(fd + 1, NULL, &writes, NULL, &timeout) == 1 && FD_ISSET(fd, &writes) ? 0 : -1;
    }
#ifdef __APPLE__
    if (strcmp(network, "tcp-kqueue") == 0) {
        int queue = kqueue();
        if (queue < 0) return -1;
        struct kevent change, event;
        EV_SET(&change, fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, (void *)0x1234);
        struct timespec timeout = {.tv_sec = 5};
        int ready = kevent(queue, &change, 1, &event, 1, &timeout);
        close(queue);
        return ready == 1 && event.filter == EVFILT_WRITE && event.udata == (void *)0x1234 ? 0 : -1;
    }
#else
    if (strcmp(network, "tcp-epoll") == 0) {
        int queue = epoll_create1(EPOLL_CLOEXEC);
        if (queue < 0) return -1;
        struct epoll_event change = {.events = EPOLLOUT, .data.u64 = 0x12345678};
        if (epoll_ctl(queue, EPOLL_CTL_ADD, fd, &change) < 0) { close(queue); return -1; }
        struct epoll_event event;
        int ready = epoll_wait(queue, &event, 1, 5000);
        close(queue);
        return ready == 1 && (event.events & EPOLLOUT) && event.data.u64 == 0x12345678 ? 0 : -1;
    }
#endif
    if (strcmp(network, "tcp-poll-write") == 0) {
        // Regression for the injector translating only POLLOUT: a client that
        // also sets POLLWRNORM (curl does) must still block until the relay
        // connect status arrives, not see the always-writable relay socket as
        // ready. On the unfixed injector POLLWRNORM leaks through and poll
        // reports ready with revents==POLLWRNORM (no POLLOUT), so this fails.
        struct pollfd pending = {.fd = fd, .events = POLLOUT | POLLWRNORM};
        return poll(&pending, 1, 5000) == 1 && (pending.revents & POLLOUT) ? 0 : -1;
    }
    struct pollfd pending = {.fd = fd, .events = POLLOUT};
    return poll(&pending, 1, 5000) == 1 && (pending.revents & POLLOUT) ? 0 : -1;
}

static int request(const char *network, const char *host, const char *port, const char *expected) {
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    int udp = strncmp(network, "udp", 3) == 0;
    hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
    if (strcmp(network, "udp-ancillary") == 0) hints.ai_family = AF_INET;
    int status = getaddrinfo(host, port, &hints, &addresses);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 1;
    }

    int fd = -1;
    int socket_family = AF_UNSPEC;
    struct sockaddr_storage destination;
    socklen_t destination_size = 0;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) continue;
        socket_family = address->ai_family;
        if (strcmp(network, "udp-ancillary") == 0) {
            int enabled = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &enabled, sizeof(enabled)) < 0) {
                close(fd); fd = -1; continue;
            }
            if (address->ai_family == AF_INET &&
                setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled)) < 0) {
                close(fd); fd = -1; continue;
            }
        }
        if (strcmp(network, "udp-unconnected") == 0) {
            memcpy(&destination, address->ai_addr, address->ai_addrlen);
            destination_size = address->ai_addrlen;
            break;
        }
        if (strncmp(network, "tcp-nonblocking", 15) == 0 || strcmp(network, "tcp-select") == 0 ||
            strcmp(network, "tcp-kqueue") == 0 || strcmp(network, "tcp-epoll") == 0 ||
            strcmp(network, "tcp-poll-write") == 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(fd); fd = -1; continue;
            }
            if (connect(fd, address->ai_addr, address->ai_addrlen) < 0 && errno != EINPROGRESS) {
                close(fd); fd = -1; continue;
            }
            if (wait_connected(fd, network) < 0) {
                close(fd); fd = -1; continue;
            }
            int connect_error = 0;
            socklen_t error_size = sizeof(connect_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &connect_error, &error_size) < 0 || connect_error != 0) {
                close(fd); fd = -1; continue;
            }
            if (fcntl(fd, F_SETFL, flags) < 0) {
                close(fd); fd = -1; continue;
            }
            break;
        }
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) break;
        if (fd >= 0) close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    const char payload[] = "native-client-probe";
    if (strcmp(network, "tcp-dup") == 0) {
        int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (duplicate < 0) {
            perror("fcntl F_DUPFD_CLOEXEC"); close(fd); return 1;
        }
        close(fd);
        fd = duplicate;
    }
    ssize_t sent;
    if (strcmp(network, "udp-ancillary") == 0) {
        struct iovec vector = {.iov_base = (void *)payload, .iov_len = sizeof(payload) - 1};
        char control[CMSG_SPACE(sizeof(int))];
        memset(control, 0, sizeof(control));
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = IPPROTO_IP;
        header->cmsg_type = IP_TTL;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(header) = 42;
        sent = sendmsg(fd, &message, 0);
    } else if (strcmp(network, "udp-unconnected") == 0) {
        sent = sendto(fd, payload, sizeof(payload) - 1, 0, (struct sockaddr *)&destination, destination_size);
    } else {
        sent = write(fd, payload, sizeof(payload) - 1);
    }
    if (sent < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    char buffer[256];
    ssize_t count;
    if (strcmp(network, "udp-ancillary") == 0) {
        struct iovec vector = {.iov_base = buffer, .iov_len = sizeof(buffer) - 1};
        char control[256];
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
        count = recvmsg(fd, &message, 0);
        int timestamp = 0, packet_info = socket_family != AF_INET;
        for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_TIMESTAMP) timestamp = 1;
            if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) packet_info = 1;
        }
        int require_packet_info = getenv("MOGATE_EXPECT_PKTINFO") != NULL;
        if (count >= 0 && (!timestamp || (require_packet_info && !packet_info) || (message.msg_flags & MSG_CTRUNC))) {
            fprintf(stderr, "missing ancillary metadata timestamp=%d pktinfo=%d flags=%d\n", timestamp, packet_info, message.msg_flags);
            close(fd);
            return 1;
        }
    } else {
        count = strcmp(network, "udp-unconnected") == 0
            ? recvfrom(fd, buffer, sizeof(buffer) - 1, 0, NULL, NULL)
            : read(fd, buffer, sizeof(buffer) - 1);
    }
    close(fd);
    if (count < 0) {
        perror("read");
        return 1;
    }
    buffer[count] = '\0';
    if (strcmp(buffer, expected) != 0) {
        fprintf(stderr, "response %s, expected %s\n", buffer, expected);
        return 1;
    }
    printf("%s", buffer);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "hold") == 0) {
        sleep(60);
        return 0;
    }
    if (argc != 5) {
        fprintf(stderr, "usage: %s tcp|tcp-nonblocking|tcp-select|tcp-kqueue|tcp-epoll|tcp-poll-write|tcp-dup|udp|udp-unconnected|udp-ancillary host port expected\n", argv[0]);
        return 2;
    }
    return request(argv[1], argv[2], argv[3], argv[4]);
}
