//go:build linux || darwin

package main

/*
#cgo linux LDFLAGS: -ldl -pthread
#cgo darwin CFLAGS: -Wno-deprecated-declarations
#cgo darwin LDFLAGS: -ldl -pthread

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include "protocol_generated.h"
#ifdef __APPLE__
#include "sip_darwin.h"
#endif

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#define MG_MAX_DNS_RESULTS 1024

#define MG_FILE_WRITE_ONLY 1
#define MG_FILE_READ_WRITE 2
#define MG_FILE_CREATE (1U << 2)
#define MG_FILE_TRUNCATE (1U << 3)
#define MG_FILE_APPEND (1U << 4)
#define MG_FILE_EXCLUSIVE (1U << 5)

#define MG_CMSG_PKTINFO4 (1U << 0)
#define MG_CMSG_PKTINFO6 (1U << 1)
#define MG_CMSG_TIMESTAMP (1U << 2)
#define MG_CMSG_TIMESTAMPNS (1U << 3)
#define MG_CMSG_HOP4 (1U << 4)
#define MG_CMSG_HOP6 (1U << 5)
#define MG_CMSG_TOS4 (1U << 6)
#define MG_CMSG_TCLASS6 (1U << 7)

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*socket_fn)(int, int, int);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef int (*close_fn)(int);
typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef off_t (*lseek_fn)(int, off_t, int);
typedef int (*fstat_fn)(int, struct stat *);
typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*fcntl_fn)(int, int, ...);
typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);
typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef int (*poll_fn)(struct pollfd *, nfds_t, int);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef int (*select_fn)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#ifndef __APPLE__
typedef int (*dup3_fn)(int, int, int);
typedef int (*epoll_ctl_fn)(int, int, int, struct epoll_event *);
typedef int (*epoll_wait_fn)(int, struct epoll_event *, int, int);
typedef int (*epoll_pwait_fn)(int, struct epoll_event *, int, int, const sigset_t *);
#else
typedef int (*kevent_fn)(int, const struct kevent *, int, struct kevent *, int, const struct timespec *);
#endif

enum mg_descriptor_kind {
	MG_DESCRIPTOR_FILE = 1,
	MG_DESCRIPTOR_UDP_CONNECTED = 2,
	MG_DESCRIPTOR_UDP_UNCONNECTED = 3,
	MG_DESCRIPTOR_TCP_PENDING = 4,
	MG_DESCRIPTOR_TCP_CONNECTED = 5,
	MG_DESCRIPTOR_TCP_FAILED = 6
};

struct mg_virtual_descriptor {
	int kind;
	unsigned int references;
	int connect_error;
	int error_reported;
	struct sockaddr_storage peer;
	socklen_t peer_size;
	unsigned char *peek_payload;
	uint32_t peek_size;
	unsigned char peek_metadata[MG_DATAGRAM_METADATA_SIZE];
	uint32_t ancillary_options;
	struct sockaddr_storage peek_source;
	socklen_t peek_source_size;
	pthread_mutex_t io_lock;
	pthread_mutex_t read_lock;
	pthread_mutex_t write_lock;
	struct mg_virtual_descriptor *retired_next;
};

struct mg_descriptor_entry {
	int fd;
	dev_t device;
	ino_t inode;
	struct mg_virtual_descriptor *descriptor;
	struct mg_descriptor_entry *next;
};

static connect_fn mg_real_connect;
static socket_fn mg_real_socket;
static read_fn mg_real_read;
static write_fn mg_real_write;
static send_fn mg_real_send;
static recv_fn mg_real_recv;
static sendto_fn mg_real_sendto;
static recvfrom_fn mg_real_recvfrom;
static close_fn mg_real_close;
static open_fn mg_real_open;
static openat_fn mg_real_openat;
static lseek_fn mg_real_lseek;
static fstat_fn mg_real_fstat;
static getaddrinfo_fn mg_real_getaddrinfo;
static freeaddrinfo_fn mg_real_freeaddrinfo;
static dup_fn mg_real_dup;
static dup2_fn mg_real_dup2;
static fcntl_fn mg_real_fcntl;
static getsockopt_fn mg_real_getsockopt;
static setsockopt_fn mg_real_setsockopt;
static poll_fn mg_real_poll;
static sendmsg_fn mg_real_sendmsg;
static recvmsg_fn mg_real_recvmsg;
static select_fn mg_real_select;
#ifndef __APPLE__
static dup3_fn mg_real_dup3;
static epoll_ctl_fn mg_real_epoll_ctl;
static epoll_wait_fn mg_real_epoll_wait;
static epoll_pwait_fn mg_real_epoll_pwait;
#else
static kevent_fn mg_real_kevent;
#endif
static pthread_once_t mg_symbols_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mg_descriptor_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mg_dns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mg_descriptor_entry *mg_descriptors;
static struct mg_virtual_descriptor *mg_retired_descriptors;
#ifndef __APPLE__
struct mg_epoll_watch {
	int epoll_fd;
	int fd;
	uint64_t token;
	struct epoll_event original;
	struct mg_epoll_watch *next;
};
static pthread_mutex_t mg_epoll_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mg_epoll_watch *mg_epoll_watches;
static uint64_t mg_epoll_token = 1;
#else
struct mg_kqueue_watch {
	int queue_fd;
	uintptr_t ident;
	uint64_t token;
	struct kevent original;
	struct mg_kqueue_watch *next;
};
static pthread_mutex_t mg_kqueue_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mg_kqueue_watch *mg_kqueue_watches;
static uint64_t mg_kqueue_token = 1;
#endif
static struct addrinfo *mg_dns_heads[MG_MAX_DNS_RESULTS];
static volatile int mg_ready;
static __thread int mg_inside;
#ifdef __APPLE__
// mg_self_path caches this injector dylib's own filesystem path (via dladdr at
// load), so the D1 exec detours can re-assert DYLD_INSERT_LIBRARIES=<self> in a
// child's environment. Empty until mg_initialize runs, or if dladdr fails.
static char mg_self_path[PATH_MAX];
// Real exec-family entry points, resolved ONCE at load in mg_initialize (never
// lazily). Under Rosetta the __DATA,__interpose table also rewrites dlsym
// results, so resolving these on the first hook call — when the interpose is
// fully live — returns our own hook and the detour's real() call recurses
// forever. At constructor time the resolver still returns the real libSystem
// symbol; this is the same reason the syscall reals (mg_real_connect etc.)
// resolve in mg_initialize rather than on first use.
static mg_sip_execve_fn mg_real_execve;
static mg_sip_execvp_fn mg_real_execvp;
static mg_sip_spawn_fn mg_real_posix_spawn;
static mg_sip_spawn_fn mg_real_posix_spawnp;
#endif

#ifdef __APPLE__
static int mg_raw_close(int fd) {
	return (int)syscall(SYS_close, fd);
}
static int mg_raw_dup(int fd) {
	return (int)syscall(SYS_dup, fd);
}
static int mg_raw_dup2(int oldfd, int newfd) {
	return (int)syscall(SYS_dup2, oldfd, newfd);
}
static int mg_raw_fcntl(int fd, int command, ...) {
	va_list args; va_start(args, command);
	void *argument = (command == F_GETFD || command == F_GETFL) ? NULL : va_arg(args, void *);
	va_end(args);
	return (int)syscall(SYS_fcntl, fd, command, argument);
}
static int mg_raw_getsockopt(int fd, int level, int option, void *value, socklen_t *size) {
	return (int)syscall(SYS_getsockopt, fd, level, option, value, size);
}
static int mg_raw_setsockopt(int fd, int level, int option, const void *value, socklen_t size) {
	return (int)syscall(SYS_setsockopt, fd, level, option, value, size);
}
static int mg_raw_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
	return (int)syscall(SYS_poll, descriptors, count, timeout);
}
static int mg_raw_select(int count, fd_set *read_set, fd_set *write_set, fd_set *error_set, struct timeval *timeout) {
	return (int)syscall(SYS_select, count, read_set, write_set, error_set, timeout);
}
static ssize_t mg_raw_sendmsg(int fd, const struct msghdr *message, int flags) {
	return (ssize_t)syscall(SYS_sendmsg, fd, message, flags);
}
static ssize_t mg_raw_recvmsg(int fd, struct msghdr *message, int flags) {
	return (ssize_t)syscall(SYS_recvmsg, fd, message, flags);
}
static int mg_raw_kevent(int queue_fd, const struct kevent *changes, int change_count,
	struct kevent *events, int event_count, const struct timespec *timeout) {
	return (int)syscall(SYS_kevent, queue_fd, changes, change_count, events, event_count, timeout);
}
#endif

static void *mg_next_symbol(const char *name) {
#ifdef __APPLE__
	static void *libc;
	static void *libinfo;
	if (!libc) libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOW | RTLD_LOCAL);
	if (!libinfo) libinfo = dlopen("/usr/lib/system/libsystem_info.dylib", RTLD_NOW | RTLD_LOCAL);
	void *symbol = libc ? dlsym(libc, name) : NULL;
	if (!symbol && libinfo) symbol = dlsym(libinfo, name);
	return symbol;
#else
	return dlsym(RTLD_NEXT, name);
#endif
}

static void mg_resolve_symbols_once(void) {
	mg_inside++;
#ifdef __APPLE__
	mg_real_read = (read_fn)mg_next_symbol("read$NOCANCEL");
	mg_real_write = (write_fn)mg_next_symbol("write$NOCANCEL");
	mg_real_send = (send_fn)mg_next_symbol("send$NOCANCEL");
	mg_real_recv = (recv_fn)mg_next_symbol("recv$NOCANCEL");
	mg_real_sendto = (sendto_fn)mg_next_symbol("sendto$NOCANCEL");
	mg_real_recvfrom = (recvfrom_fn)mg_next_symbol("recvfrom$NOCANCEL");
	mg_real_close = mg_raw_close;
	mg_real_connect = (connect_fn)mg_next_symbol("connect$NOCANCEL");
	mg_real_open = (open_fn)mg_next_symbol("open$NOCANCEL");
	mg_real_openat = (openat_fn)mg_next_symbol("openat$NOCANCEL");
#else
	mg_real_read = (read_fn)mg_next_symbol("read");
	mg_real_write = (write_fn)mg_next_symbol("write");
	mg_real_send = (send_fn)mg_next_symbol("send");
	mg_real_recv = (recv_fn)mg_next_symbol("recv");
	mg_real_sendto = (sendto_fn)mg_next_symbol("sendto");
	mg_real_recvfrom = (recvfrom_fn)mg_next_symbol("recvfrom");
	mg_real_close = (close_fn)mg_next_symbol("close");
	mg_real_connect = (connect_fn)mg_next_symbol("connect");
	mg_real_open = (open_fn)mg_next_symbol("open");
	mg_real_openat = (openat_fn)mg_next_symbol("openat");
#endif
	mg_real_socket = (socket_fn)mg_next_symbol("socket");
	mg_real_lseek = (lseek_fn)mg_next_symbol("lseek");
	mg_real_fstat = (fstat_fn)mg_next_symbol("fstat");
	mg_real_getaddrinfo = (getaddrinfo_fn)mg_next_symbol("getaddrinfo");
	mg_real_freeaddrinfo = (freeaddrinfo_fn)mg_next_symbol("freeaddrinfo");

#ifdef __APPLE__
	mg_real_dup = mg_raw_dup;
	mg_real_dup2 = mg_raw_dup2;
	mg_real_fcntl = mg_raw_fcntl;
	mg_real_getsockopt = mg_raw_getsockopt;
	mg_real_setsockopt = mg_raw_setsockopt;
	mg_real_poll = mg_raw_poll;
	mg_real_select = mg_raw_select;
	mg_real_sendmsg = mg_raw_sendmsg;
	mg_real_recvmsg = mg_raw_recvmsg;
	mg_real_kevent = mg_raw_kevent;
#else
	mg_real_dup = (dup_fn)mg_next_symbol("dup");
	mg_real_dup2 = (dup2_fn)mg_next_symbol("dup2");
	mg_real_fcntl = (fcntl_fn)mg_next_symbol("fcntl");
	mg_real_getsockopt = (getsockopt_fn)mg_next_symbol("getsockopt");
	mg_real_setsockopt = (setsockopt_fn)mg_next_symbol("setsockopt");
	mg_real_poll = (poll_fn)mg_next_symbol("poll");
	mg_real_sendmsg = (sendmsg_fn)mg_next_symbol("sendmsg");
	mg_real_recvmsg = (recvmsg_fn)mg_next_symbol("recvmsg");
	mg_real_select = (select_fn)mg_next_symbol("select");
	mg_real_dup3 = (dup3_fn)mg_next_symbol("dup3");
	mg_real_epoll_ctl = (epoll_ctl_fn)mg_next_symbol("epoll_ctl");
	mg_real_epoll_wait = (epoll_wait_fn)mg_next_symbol("epoll_wait");
	mg_real_epoll_pwait = (epoll_pwait_fn)mg_next_symbol("epoll_pwait");
#endif
	mg_inside--;
}

static int mg_symbols(void) {
	pthread_once(&mg_symbols_once, mg_resolve_symbols_once);
	if (!mg_real_connect || !mg_real_socket || !mg_real_read || !mg_real_write ||
		!mg_real_send || !mg_real_recv || !mg_real_sendto || !mg_real_recvfrom ||
		!mg_real_close || !mg_real_open || !mg_real_lseek || !mg_real_fstat ||
		!mg_real_getaddrinfo || !mg_real_freeaddrinfo || !mg_real_dup ||
		!mg_real_dup2 || !mg_real_fcntl || !mg_real_getsockopt || !mg_real_setsockopt || !mg_real_poll ||
		!mg_real_sendmsg || !mg_real_recvmsg || !mg_real_select) {
		errno = ENOSYS;
		return -1;
	}
#ifdef __APPLE__
	if (!mg_real_kevent) { errno = ENOSYS; return -1; }
#else
	if (!mg_real_epoll_ctl || !mg_real_epoll_wait || !mg_real_epoll_pwait) {
		errno = ENOSYS; return -1;
	}
#endif
	return 0;
}

#ifdef __APPLE__
static int mg_connect_hook(int sockfd, const struct sockaddr *address, socklen_t address_len);
#endif

__attribute__((constructor)) static void mg_initialize(void) {
	if (mg_symbols() == 0) mg_ready = 1;
#ifdef __APPLE__
	Dl_info info;
	if (dladdr((void *)&mg_connect_hook, &info) && info.dli_fname) {
		size_t n = strlen(info.dli_fname);
		if (n < sizeof(mg_self_path)) {
			memcpy(mg_self_path, info.dli_fname, n);
			mg_self_path[n] = 0;
		}
	}
	// Resolve the real exec-family entry points by DIRECT symbol reference, not
	// dlsym. A direct reference is bound by the static linker to libSystem's real
	// implementation; dlsym (and dlsym(RTLD_NEXT)) instead return our own
	// interposer under Rosetta, because the __DATA,__interpose table rewrites
	// dlsym results there. Taking the address directly is the only resolution
	// that reliably skips the interpose on both native arm64 and Rosetta x86_64.
	mg_real_execve = (mg_sip_execve_fn)&execve;
	mg_real_execvp = (mg_sip_execvp_fn)&execvp;
	mg_real_posix_spawn = (mg_sip_spawn_fn)&posix_spawn;
	mg_real_posix_spawnp = (mg_sip_spawn_fn)&posix_spawnp;
#endif
}

static void mg_put_u32(unsigned char *out, uint32_t value) {
	out[0] = (unsigned char)(value >> 24);
	out[1] = (unsigned char)(value >> 16);
	out[2] = (unsigned char)(value >> 8);
	out[3] = (unsigned char)value;
}

static uint32_t mg_get_u32(const unsigned char *in) {
	return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
		((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void mg_put_u64(unsigned char *out, uint64_t value) {
	mg_put_u32(out, (uint32_t)(value >> 32));
	mg_put_u32(out + 4, (uint32_t)value);
}

static uint64_t mg_get_u64(const unsigned char *in) {
	return ((uint64_t)mg_get_u32(in) << 32) | mg_get_u32(in + 4);
}

static int mg_encode_address(unsigned char *out, size_t capacity,
	const struct sockaddr *address, socklen_t address_size) {
	(void)address_size;
	if (!address) { errno = EDESTADDRREQ; return -1; }
	memset(out, 0, capacity);
	if (address->sa_family == AF_INET) {
		if (capacity < MG_ADDRESS_IPV4_SIZE) { errno = EMSGSIZE; return -1; }
		const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
		out[0] = MG_ADDRESS_FAMILY_IPV4;
		memcpy(out + 2, &ipv4->sin_port, 2);
		memcpy(out + MG_ADDRESS_HEADER_SIZE, &ipv4->sin_addr, 4);
		return MG_ADDRESS_IPV4_SIZE;
	}
	if (address->sa_family == AF_INET6) {
		if (capacity < MG_ADDRESS_IPV6_SIZE) { errno = EMSGSIZE; return -1; }
		const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
		out[0] = MG_ADDRESS_FAMILY_IPV6;
		memcpy(out + 2, &ipv6->sin6_port, 2);
		mg_put_u32(out + 4, ipv6->sin6_scope_id);
		memcpy(out + MG_ADDRESS_HEADER_SIZE, &ipv6->sin6_addr, 16);
		return MG_ADDRESS_IPV6_SIZE;
	}
	errno = EAFNOSUPPORT;
	return -1;
}

static int mg_decode_address(const unsigned char *in, uint32_t size,
	struct sockaddr_storage *address, socklen_t *address_size) {
	if (!in || size < MG_ADDRESS_HEADER_SIZE || !address || !address_size) {
		errno = EPROTO; return -1;
	}
	memset(address, 0, sizeof(*address));
	if (in[0] == MG_ADDRESS_FAMILY_IPV4 && size >= MG_ADDRESS_IPV4_SIZE) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
		ipv4->sin_family = AF_INET;
#ifdef __APPLE__
		ipv4->sin_len = sizeof(*ipv4);
#endif
		memcpy(&ipv4->sin_port, in + 2, 2);
		memcpy(&ipv4->sin_addr, in + MG_ADDRESS_HEADER_SIZE, 4);
		*address_size = sizeof(*ipv4);
		return MG_ADDRESS_IPV4_SIZE;
	}
	if (in[0] == MG_ADDRESS_FAMILY_IPV6 && size >= MG_ADDRESS_IPV6_SIZE) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
		ipv6->sin6_family = AF_INET6;
#ifdef __APPLE__
		ipv6->sin6_len = sizeof(*ipv6);
#endif
		memcpy(&ipv6->sin6_port, in + 2, 2);
		ipv6->sin6_scope_id = mg_get_u32(in + 4);
		memcpy(&ipv6->sin6_addr, in + MG_ADDRESS_HEADER_SIZE, 16);
		*address_size = sizeof(*ipv6);
		return MG_ADDRESS_IPV6_SIZE;
	}
	errno = EPROTO;
	return -1;
}

static uint32_t mg_udp_option_bit(int level, int option) {
	if (level == IPPROTO_IP && option == IP_PKTINFO) return MG_CMSG_PKTINFO4;
#ifdef IPV6_RECVPKTINFO
	if (level == IPPROTO_IPV6 && option == IPV6_RECVPKTINFO) return MG_CMSG_PKTINFO6;
#endif
#ifdef IPV6_PKTINFO
	if (level == IPPROTO_IPV6 && option == IPV6_PKTINFO) return MG_CMSG_PKTINFO6;
#endif
	if (level == SOL_SOCKET && option == SO_TIMESTAMP) return MG_CMSG_TIMESTAMP;
#ifdef SO_TIMESTAMPNS
	if (level == SOL_SOCKET && option == SO_TIMESTAMPNS) return MG_CMSG_TIMESTAMPNS;
#endif
	if (level == IPPROTO_IP && option == IP_RECVTTL) return MG_CMSG_HOP4;
#ifdef IPV6_RECVHOPLIMIT
	if (level == IPPROTO_IPV6 && option == IPV6_RECVHOPLIMIT) return MG_CMSG_HOP6;
#endif
	if (level == IPPROTO_IP && option == IP_RECVTOS) return MG_CMSG_TOS4;
	if (level == IPPROTO_IPV6 && option == IPV6_RECVTCLASS) return MG_CMSG_TCLASS6;
	return 0;
}

static uint32_t mg_capture_udp_options(int fd) {
	uint32_t options = 0;
	const struct { int level; int option; uint32_t bit; } candidates[] = {
		{IPPROTO_IP, IP_PKTINFO, MG_CMSG_PKTINFO4},
		{SOL_SOCKET, SO_TIMESTAMP, MG_CMSG_TIMESTAMP},
		{IPPROTO_IP, IP_RECVTTL, MG_CMSG_HOP4},
		{IPPROTO_IP, IP_RECVTOS, MG_CMSG_TOS4},
		{IPPROTO_IPV6, IPV6_RECVTCLASS, MG_CMSG_TCLASS6},
#ifdef IPV6_RECVPKTINFO
		{IPPROTO_IPV6, IPV6_RECVPKTINFO, MG_CMSG_PKTINFO6},
#endif
#ifdef IPV6_RECVHOPLIMIT
		{IPPROTO_IPV6, IPV6_RECVHOPLIMIT, MG_CMSG_HOP6},
#endif
#ifdef SO_TIMESTAMPNS
		{SOL_SOCKET, SO_TIMESTAMPNS, MG_CMSG_TIMESTAMPNS},
#endif
	};
	for (size_t index = 0; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
		int enabled = 0;
		socklen_t size = sizeof(enabled);
		if (mg_real_getsockopt(fd, candidates[index].level, candidates[index].option, &enabled, &size) == 0 && enabled)
			options |= candidates[index].bit;
	}
	return options;
}

static int mg_encode_datagram_metadata(unsigned char out[MG_DATAGRAM_METADATA_SIZE],
	const struct msghdr *message) {
	memset(out, 0, MG_DATAGRAM_METADATA_SIZE);
	if (!message || !message->msg_control || message->msg_controllen == 0) return 0;
	uint32_t flags = 0;
	for (struct cmsghdr *control = CMSG_FIRSTHDR(message); control;
		control = CMSG_NXTHDR((struct msghdr *)message, control)) {
		if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_RIGHTS) {
			errno = ENOTSUP;
			return -1;
		}
		if (control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_PKTINFO &&
			control->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
			const struct in_pktinfo *info = (const struct in_pktinfo *)CMSG_DATA(control);
			struct sockaddr_in source;
			memset(&source, 0, sizeof(source));
			source.sin_family = AF_INET;
			source.sin_addr = info->ipi_spec_dst.s_addr ? info->ipi_spec_dst : info->ipi_addr;
			if (mg_encode_address(out + 24, MG_ADDRESS_IPV6_SIZE, (struct sockaddr *)&source, sizeof(source)) < 0) return -1;
			mg_put_u32(out + 4, (uint32_t)info->ipi_ifindex);
			flags |= MG_DATAGRAM_DESTINATION | MG_DATAGRAM_INTERFACE;
			continue;
		}
#ifdef IPV6_PKTINFO
		if (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_PKTINFO &&
			control->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
			const struct in6_pktinfo *info = (const struct in6_pktinfo *)CMSG_DATA(control);
			struct sockaddr_in6 source;
			memset(&source, 0, sizeof(source));
			source.sin6_family = AF_INET6;
			source.sin6_addr = info->ipi6_addr;
			if (mg_encode_address(out + 24, MG_ADDRESS_IPV6_SIZE, (struct sockaddr *)&source, sizeof(source)) < 0) return -1;
			mg_put_u32(out + 4, info->ipi6_ifindex);
			flags |= MG_DATAGRAM_DESTINATION | MG_DATAGRAM_INTERFACE;
			continue;
		}
#endif
		if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TTL)
#ifdef IPV6_HOPLIMIT
			|| (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_HOPLIMIT)
#endif
		) {
			if (control->cmsg_len < CMSG_LEN(sizeof(int))) { errno = EINVAL; return -1; }
			mg_put_u32(out + 8, (uint32_t)*(const int *)CMSG_DATA(control));
			flags |= MG_DATAGRAM_HOP_LIMIT;
			continue;
		}
		if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TOS)
#ifdef IPV6_TCLASS
			|| (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_TCLASS)
#endif
		) {
			if (control->cmsg_len < CMSG_LEN(sizeof(int))) { errno = EINVAL; return -1; }
			mg_put_u32(out + 12, (uint32_t)*(const int *)CMSG_DATA(control));
			flags |= MG_DATAGRAM_TRAFFIC_CLASS;
			continue;
		}
		errno = ENOTSUP;
		return -1;
	}
	mg_put_u32(out, flags);
	return 0;
}

static int mg_append_control(struct msghdr *message, size_t capacity, size_t *used,
	int level, int type, const void *data, size_t size) {
	size_t space = CMSG_SPACE(size);
	if (*used + space > capacity) {
		message->msg_flags |= MSG_CTRUNC;
		return 0;
	}
	struct cmsghdr *control = (struct cmsghdr *)((unsigned char *)message->msg_control + *used);
	memset(control, 0, space);
	control->cmsg_level = level;
	control->cmsg_type = type;
	control->cmsg_len = CMSG_LEN(size);
	memcpy(CMSG_DATA(control), data, size);
	*used += space;
	message->msg_controllen = *used;
	return 1;
}

static void mg_decode_datagram_metadata(const unsigned char in[MG_DATAGRAM_METADATA_SIZE],
	uint32_t options, struct msghdr *message) {
	if (!message || !message->msg_control || message->msg_controllen == 0) return;
	size_t capacity = message->msg_controllen;
	size_t used = 0;
	message->msg_controllen = 0;
	uint32_t flags = mg_get_u32(in);
	uint32_t interface = mg_get_u32(in + 4);
	if ((flags & MG_DATAGRAM_DESTINATION) && (options & (MG_CMSG_PKTINFO4 | MG_CMSG_PKTINFO6))) {
		struct sockaddr_storage destination;
		socklen_t destination_size = 0;
		if (mg_decode_address(in + 24, MG_ADDRESS_IPV6_SIZE, &destination, &destination_size) >= 0) {
			if (destination.ss_family == AF_INET && (options & MG_CMSG_PKTINFO4)) {
				struct in_pktinfo info;
				memset(&info, 0, sizeof(info));
				info.ipi_ifindex = interface;
				info.ipi_addr = ((struct sockaddr_in *)&destination)->sin_addr;
				info.ipi_spec_dst = info.ipi_addr;
				(void)mg_append_control(message, capacity, &used, IPPROTO_IP, IP_PKTINFO, &info, sizeof(info));
			}
#ifdef IPV6_PKTINFO
			if (destination.ss_family == AF_INET6 && (options & MG_CMSG_PKTINFO6)) {
				struct in6_pktinfo info;
				memset(&info, 0, sizeof(info));
				info.ipi6_ifindex = interface;
				info.ipi6_addr = ((struct sockaddr_in6 *)&destination)->sin6_addr;
				(void)mg_append_control(message, capacity, &used, IPPROTO_IPV6, IPV6_PKTINFO, &info, sizeof(info));
			}
#endif
		}
	}
	if (flags & MG_DATAGRAM_HOP_LIMIT) {
		int value = (int)mg_get_u32(in + 8);
		if (options & MG_CMSG_HOP4) (void)mg_append_control(message, capacity, &used, IPPROTO_IP, IP_TTL, &value, sizeof(value));
#ifdef IPV6_HOPLIMIT
		if (options & MG_CMSG_HOP6) (void)mg_append_control(message, capacity, &used, IPPROTO_IPV6, IPV6_HOPLIMIT, &value, sizeof(value));
#endif
	}
	if (flags & MG_DATAGRAM_TRAFFIC_CLASS) {
		int value = (int)mg_get_u32(in + 12);
		if (options & MG_CMSG_TOS4) (void)mg_append_control(message, capacity, &used, IPPROTO_IP, IP_TOS, &value, sizeof(value));
#ifdef IPV6_TCLASS
		if (options & MG_CMSG_TCLASS6) (void)mg_append_control(message, capacity, &used, IPPROTO_IPV6, IPV6_TCLASS, &value, sizeof(value));
#endif
	}
	if (flags & MG_DATAGRAM_TIMESTAMP) {
		int64_t nanoseconds = (int64_t)mg_get_u64(in + 16);
		if (options & MG_CMSG_TIMESTAMP) {
			struct timeval value = {.tv_sec = nanoseconds / 1000000000LL, .tv_usec = (nanoseconds % 1000000000LL) / 1000};
			(void)mg_append_control(message, capacity, &used, SOL_SOCKET, SCM_TIMESTAMP, &value, sizeof(value));
		}
#ifdef SCM_TIMESTAMPNS
		if (options & MG_CMSG_TIMESTAMPNS) {
			struct timespec value = {.tv_sec = nanoseconds / 1000000000LL, .tv_nsec = nanoseconds % 1000000000LL};
			(void)mg_append_control(message, capacity, &used, SOL_SOCKET, SCM_TIMESTAMPNS, &value, sizeof(value));
		}
#endif
	}
}

static int mg_write_all(int fd, const void *data, size_t size) {
	const unsigned char *cursor = (const unsigned char *)data;
	while (size > 0) {
		ssize_t written = mg_real_write(fd, cursor, size);
		if (written < 0 && errno == EINTR) continue;
		if (written <= 0) return -1;
		cursor += written;
		size -= (size_t)written;
	}
	return 0;
}

static int mg_read_all(int fd, void *data, size_t size) {
	unsigned char *cursor = (unsigned char *)data;
	while (size > 0) {
		ssize_t count = mg_real_read(fd, cursor, size);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) {
			if (count == 0) errno = EPIPE;
			return -1;
		}
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

static int mg_send_frame(int fd, unsigned char operation, const void *payload, uint32_t size) {
	unsigned char header[MG_HEADER_SIZE] = {'M', 'O', 'G', 'A', 1, operation, 0, 0, 0, 0, 0, 0};
	if (size > MG_MAX_PAYLOAD) {
		errno = E2BIG;
		return -1;
	}
	mg_put_u32(header + 8, size);
	if (mg_write_all(fd, header, sizeof(header)) < 0) return -1;
	if (size > 0 && mg_write_all(fd, payload, size) < 0) return -1;
	return 0;
}

static int mg_receive_frame(int fd, unsigned char expected, unsigned char **payload, uint32_t *size) {
	unsigned char header[MG_HEADER_SIZE];
	if (mg_read_all(fd, header, sizeof(header)) < 0) return -1;
	if (memcmp(header, "MOGA", 4) != 0 || header[4] != 1 || header[5] != expected) {
		errno = EPROTO;
		return -1;
	}
	*size = mg_get_u32(header + 8);
	if (*size > MG_MAX_PAYLOAD) {
		errno = E2BIG;
		return -1;
	}
	*payload = (unsigned char *)malloc((size_t)*size + 1);
	if (!*payload) return -1;
	if (*size > 0 && mg_read_all(fd, *payload, *size) < 0) {
		free(*payload);
		*payload = NULL;
		return -1;
	}
	(*payload)[*size] = 0;
	return 0;
}

static int mg_status(unsigned char *payload, uint32_t size, unsigned char **data, uint32_t *data_size) {
	if (size < 4) {
		errno = EPROTO;
		return -1;
	}
	uint32_t remote_errno = mg_get_u32(payload);
	if (remote_errno != 0) {
		errno = (int)remote_errno;
		return -1;
	}
	*data = payload + 4;
	*data_size = size - 4;
	return 0;
}

static int mg_agent_connection(void) {
	const char *path = getenv("MOGATE_SOCKET");
	if (!path || !*path) {
		errno = ENOENT;
		return -1;
	}
	if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	int fd = mg_real_socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, path, sizeof(address.sun_path) - 1);
	if (mg_real_connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
		int saved = errno;
		mg_real_close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

static struct mg_descriptor_entry *mg_find_entry_locked(int fd) {
	for (struct mg_descriptor_entry *entry = mg_descriptors; entry; entry = entry->next) {
		if (entry->fd == fd) return entry;
	}
	return NULL;
}

static struct mg_virtual_descriptor *mg_descriptor_for(int fd) {
	struct mg_virtual_descriptor *result = NULL;
	pthread_mutex_lock(&mg_descriptor_lock);
	struct mg_descriptor_entry *entry = mg_find_entry_locked(fd);
	if (entry) {
		struct stat current;
		if (!mg_real_fstat || mg_real_fstat(fd, &current) < 0 || current.st_dev != entry->device ||
			current.st_ino != entry->inode) {
			entry = NULL;
		} else {
			result = entry->descriptor;
		}
	}
	pthread_mutex_unlock(&mg_descriptor_lock);
	return result;
}

static int mg_register_descriptor(int fd, int kind, const struct sockaddr *peer, socklen_t peer_size) {
	struct stat identity;
	if (fd < 0 || !mg_real_fstat || mg_real_fstat(fd, &identity) < 0) return -1;
	struct mg_virtual_descriptor *descriptor = calloc(1, sizeof(*descriptor));
	struct mg_descriptor_entry *entry = calloc(1, sizeof(*entry));
	if (!descriptor || !entry) {
		free(descriptor); free(entry); errno = ENOMEM; return -1;
	}
	descriptor->kind = kind;
	descriptor->references = 1;
	pthread_mutex_init(&descriptor->io_lock, NULL);
	pthread_mutex_init(&descriptor->read_lock, NULL);
	pthread_mutex_init(&descriptor->write_lock, NULL);
	if (peer && peer_size <= sizeof(descriptor->peer)) {
		memcpy(&descriptor->peer, peer, peer_size);
		descriptor->peer_size = peer_size;
	}
	entry->fd = fd;
	entry->device = identity.st_dev;
	entry->inode = identity.st_ino;
	entry->descriptor = descriptor;
	pthread_mutex_lock(&mg_descriptor_lock);
	entry->next = mg_descriptors;
	mg_descriptors = entry;
	pthread_mutex_unlock(&mg_descriptor_lock);
	return 0;
}

static int mg_clone_descriptor(int source, int destination) {
	struct stat identity;
	if (!mg_real_fstat || mg_real_fstat(destination, &identity) < 0) return -1;
	struct mg_descriptor_entry *copy = calloc(1, sizeof(*copy));
	if (!copy) { errno = ENOMEM; return -1; }
	pthread_mutex_lock(&mg_descriptor_lock);
	struct mg_descriptor_entry *source_entry = mg_find_entry_locked(source);
	if (!source_entry) {
		pthread_mutex_unlock(&mg_descriptor_lock);
		free(copy);
		return 0;
	}
	copy->fd = destination;
	copy->device = identity.st_dev;
	copy->inode = identity.st_ino;
	copy->descriptor = source_entry->descriptor;
	copy->descriptor->references++;
	copy->next = mg_descriptors;
	mg_descriptors = copy;
	pthread_mutex_unlock(&mg_descriptor_lock);
	return 0;
}

static struct mg_virtual_descriptor *mg_detach_descriptor(int fd, int *last) {
	struct mg_virtual_descriptor *descriptor = NULL;
	*last = 0;
	pthread_mutex_lock(&mg_descriptor_lock);
	struct mg_descriptor_entry **cursor = &mg_descriptors;
	while (*cursor) {
		if ((*cursor)->fd == fd) {
			struct mg_descriptor_entry *removed = *cursor;
			*cursor = removed->next;
			descriptor = removed->descriptor;
			if (descriptor->references > 0) descriptor->references--;
			*last = descriptor->references == 0;
			free(removed);
			break;
		}
		cursor = &(*cursor)->next;
	}
	pthread_mutex_unlock(&mg_descriptor_lock);
	return descriptor;
}

static void mg_free_descriptor(struct mg_virtual_descriptor *descriptor) {
	if (!descriptor) return;
	// A concurrent operation may still hold a borrowed descriptor pointer after
	// close. Retire it until process teardown instead of risking a use-after-free.
	pthread_mutex_lock(&mg_descriptor_lock);
	descriptor->retired_next = mg_retired_descriptors;
	mg_retired_descriptors = descriptor;
	pthread_mutex_unlock(&mg_descriptor_lock);
}

__attribute__((destructor)) static void mg_destroy_retired_descriptors(void) {
	struct mg_virtual_descriptor *descriptor = mg_retired_descriptors;
	while (descriptor) {
		struct mg_virtual_descriptor *next = descriptor->retired_next;
		free(descriptor->peek_payload);
		pthread_mutex_destroy(&descriptor->io_lock);
		pthread_mutex_destroy(&descriptor->read_lock);
		pthread_mutex_destroy(&descriptor->write_lock);
		free(descriptor);
		descriptor = next;
	}
}

static int mg_is_remote_file(int fd) {
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	return descriptor && descriptor->kind == MG_DESCRIPTOR_FILE;
}

static int mg_is_remote_udp(int fd) {
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	return descriptor && (descriptor->kind == MG_DESCRIPTOR_UDP_CONNECTED ||
		descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED);
}

static void mg_set_remote_file(int fd, int value) {
	if (value) (void)mg_register_descriptor(fd, MG_DESCRIPTOR_FILE, NULL, 0);
}

static void mg_set_remote_udp(int fd, int value, const struct sockaddr *peer, socklen_t peer_size) {
	if (value) (void)mg_register_descriptor(fd, MG_DESCRIPTOR_UDP_CONNECTED, peer, peer_size);
}

static uint32_t mg_normalize_open_flags(int flags) {
	uint32_t result = 0;
	if ((flags & O_ACCMODE) == O_WRONLY) result |= MG_FILE_WRITE_ONLY;
	if ((flags & O_ACCMODE) == O_RDWR) result |= MG_FILE_READ_WRITE;
	if (flags & O_CREAT) result |= MG_FILE_CREATE;
	if (flags & O_TRUNC) result |= MG_FILE_TRUNCATE;
	if (flags & O_APPEND) result |= MG_FILE_APPEND;
	if (flags & O_EXCL) result |= MG_FILE_EXCLUSIVE;
	return result;
}

static int mg_should_remote_path(const char *path) {
	const char *mode = getenv("MOGATE_FILE_MODE");
	if (!mode || strcmp(mode, "remote") != 0 || !path || path[0] != '/') return 0;
	const char *socket_path = getenv("MOGATE_SOCKET");
	if (socket_path && strcmp(path, socket_path) == 0) return 0;
	if (strncmp(path, "/dev/", 5) == 0 || strncmp(path, "/proc/", 6) == 0 ||
		strncmp(path, "/sys/", 5) == 0) return 0;
	return 1;
}

static int mg_remote_open(const char *path, int flags, mode_t mode) {
	size_t path_size = strlen(path);
	if (path_size > MG_MAX_PAYLOAD - 8) {
		errno = ENAMETOOLONG;
		return -1;
	}
	int fd = mg_agent_connection();
	if (fd < 0) return -1;
	uint32_t payload_size = (uint32_t)path_size + 8;
	unsigned char *request = (unsigned char *)malloc(payload_size);
	if (!request) {
		mg_real_close(fd);
		return -1;
	}
	mg_put_u32(request, mg_normalize_open_flags(flags));
	mg_put_u32(request + 4, (uint32_t)mode);
	memcpy(request + 8, path, path_size);
	int result = mg_send_frame(fd, MG_OP_FILE_OPEN, request, payload_size);
	free(request);
	if (result < 0) {
		mg_real_close(fd);
		return -1;
	}
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	if (mg_receive_frame(fd, MG_OP_FILE_OPEN, &response, &response_size) < 0 ||
		mg_status(response, response_size, &data, &data_size) < 0) {
		int saved = errno;
		free(response);
		mg_real_close(fd);
		errno = saved;
		return -1;
	}
	free(response);
	mg_set_remote_file(fd, 1);
	return fd;
}

static int mg_connect_hook(int sockfd, const struct sockaddr *address, socklen_t address_len) {
	if (mg_inside) {
		if (mg_real_connect) return mg_real_connect(sockfd, address, address_len);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	struct mg_virtual_descriptor *existing = mg_descriptor_for(sockfd);
	if (existing && existing->kind == MG_DESCRIPTOR_TCP_PENDING) { errno = EALREADY; return -1; }
	if (existing && existing->kind == MG_DESCRIPTOR_TCP_CONNECTED) { errno = EISCONN; return -1; }
	if (existing && existing->kind == MG_DESCRIPTOR_TCP_FAILED) { errno = existing->connect_error; return -1; }
	if (existing && existing->kind == MG_DESCRIPTOR_UDP_UNCONNECTED && address &&
		(address->sa_family == AF_INET || address->sa_family == AF_INET6) && address_len <= sizeof(existing->peer)) {
		pthread_mutex_lock(&existing->io_lock);
		memcpy(&existing->peer, address, address_len);
		existing->peer_size = address_len;
		pthread_mutex_unlock(&existing->io_lock);
		return 0;
	}
	if (!getenv("MOGATE_SOCKET") || !address ||
		(address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
		return mg_real_connect(sockfd, address, address_len);
	}
	int type = 0;
	socklen_t type_size = sizeof(type);
	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0 ||
		(type != SOCK_STREAM && type != SOCK_DGRAM)) {
		return mg_real_connect(sockfd, address, address_len);
	}
	int is_udp = type == SOCK_DGRAM;
	uint32_t udp_options = is_udp ? mg_capture_udp_options(sockfd) : 0;
	int status_flags = fcntl(sockfd, F_GETFL, 0);
	if (status_flags < 0) return mg_real_connect(sockfd, address, address_len);
	int was_nonblocking = (status_flags & O_NONBLOCK) != 0;
	char host[INET6_ADDRSTRLEN];
	char target[INET6_ADDRSTRLEN + 16];
	uint16_t port;
	if (address->sa_family == AF_INET) {
		const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
		if (!inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host))) return -1;
		port = ntohs(ipv4->sin_port);
		snprintf(target, sizeof(target), "%s:%u", host, (unsigned)port);
	} else {
		const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
		if (!inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host))) return -1;
		port = ntohs(ipv6->sin6_port);
		snprintf(target, sizeof(target), "[%s]:%u", host, (unsigned)port);
	}
	mg_inside++;
	int proxy = mg_agent_connection();
	unsigned char connect_operation = is_udp ? MG_OP_UDP_CONNECT_METADATA : MG_OP_TCP_CONNECT;
	if (proxy >= 0 && mg_send_frame(proxy, connect_operation, target, (uint32_t)strlen(target)) == 0) {
		if (was_nonblocking && !is_udp) {
			int descriptor_flags = mg_real_fcntl(sockfd, F_GETFD);
			if (mg_real_dup2(proxy, sockfd) >= 0 &&
				mg_register_descriptor(sockfd, MG_DESCRIPTOR_TCP_PENDING, address, address_len) == 0) {
				if (descriptor_flags >= 0) mg_real_fcntl(sockfd, F_SETFD, descriptor_flags);
				mg_real_fcntl(sockfd, F_SETFL, status_flags);
				mg_real_close(proxy);
				mg_inside--;
				errno = EINPROGRESS;
				return -1;
			}
			int saved = errno;
			mg_real_close(proxy);
			mg_inside--;
			errno = saved;
			return -1;
		}
		unsigned char *response = NULL, *data = NULL;
		uint32_t response_size = 0, data_size = 0;
		if (mg_receive_frame(proxy, connect_operation, &response, &response_size) == 0 &&
			mg_status(response, response_size, &data, &data_size) == 0) {
			int descriptor_flags = fcntl(sockfd, F_GETFD, 0);
			if (mg_real_dup2(proxy, sockfd) >= 0) {
				if (descriptor_flags >= 0) fcntl(sockfd, F_SETFD, descriptor_flags);
				if (was_nonblocking) fcntl(sockfd, F_SETFL, status_flags);
				if (is_udp) {
					mg_set_remote_udp(sockfd, 1, address, address_len);
					struct mg_virtual_descriptor *udp_descriptor = mg_descriptor_for(sockfd);
					if (udp_descriptor) udp_descriptor->ancillary_options = udp_options;
				}
				else (void)mg_register_descriptor(sockfd, MG_DESCRIPTOR_TCP_CONNECTED, address, address_len);
				free(response);
				mg_real_close(proxy);
				mg_inside--;
				return 0;
			}
		}
		int saved = errno;
		free(response);
		mg_real_close(proxy);
		errno = saved;
	}
	mg_inside--;
	return -1;
}

static int mg_open_hook(const char *path, int flags, ...) {
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
	}
	if (mg_inside) {
		if (mg_real_open) return mg_real_open(path, flags, mode);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (mg_should_remote_path(path)) {
		mg_inside++;
		int result = mg_remote_open(path, flags, mode);
		mg_inside--;
		return result;
	}
	return mg_real_open(path, flags, mode);
}

static int mg_openat_hook(int directory, const char *path, int flags, ...) {
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
	}
	if (mg_inside) {
		if (mg_real_openat) return mg_real_openat(directory, path, flags, mode);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (path && path[0] == '/' && mg_should_remote_path(path)) {
		mg_inside++;
		int result = mg_remote_open(path, flags, mode);
		mg_inside--;
		return result;
	}
	if (!mg_real_openat) {
		errno = ENOSYS;
		return -1;
	}
	return mg_real_openat(directory, path, flags, mode);
}

static ssize_t mg_udp_send_metadata(int fd, const void *buffer, size_t count,
	const unsigned char metadata[MG_DATAGRAM_METADATA_SIZE]) {
	if (count > MG_MAX_PAYLOAD - MG_DATAGRAM_METADATA_SIZE) count = MG_MAX_PAYLOAD - MG_DATAGRAM_METADATA_SIZE;
	unsigned char *payload = malloc(MG_DATAGRAM_METADATA_SIZE + count);
	if (!payload) { errno = ENOMEM; return -1; }
	memcpy(payload, metadata, MG_DATAGRAM_METADATA_SIZE);
	memcpy(payload + MG_DATAGRAM_METADATA_SIZE, buffer, count);
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor) { free(payload); errno = EBADF; return -1; }
	pthread_mutex_lock(&descriptor->write_lock);
	mg_inside++;
	int result = mg_send_frame(fd, MG_OP_UDP_SEND_MSG, payload, (uint32_t)(MG_DATAGRAM_METADATA_SIZE + count));
	mg_inside--;
	pthread_mutex_unlock(&descriptor->write_lock);
	free(payload);
	return result < 0 ? -1 : (ssize_t)count;
}

static ssize_t mg_udp_send_hook(int fd, const void *buffer, size_t count) {
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE] = {0};
	return mg_udp_send_metadata(fd, buffer, count, metadata);
}

static ssize_t mg_udp_receive_hook(int fd, void *buffer, size_t count, int flags,
	struct sockaddr *source, socklen_t *source_size,
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE]) {
	if (flags & MSG_PEEK) {
		errno = ENOTSUP;
		return -1;
	}
	int status_flags = fcntl(fd, F_GETFL, 0);
	int nonblocking = (status_flags >= 0 && (status_flags & O_NONBLOCK)) || (flags & MSG_DONTWAIT);
	if (nonblocking) {
		struct pollfd descriptor = {.fd = fd, .events = POLLIN};
		int ready = poll(&descriptor, 1, 0);
		if (ready <= 0 || !(descriptor.revents & (POLLIN | POLLHUP))) {
			errno = EAGAIN;
			return -1;
		}
		if (status_flags & O_NONBLOCK) fcntl(fd, F_SETFL, status_flags & ~O_NONBLOCK);
	}
	mg_inside++;
	unsigned char *response = NULL;
	uint32_t response_size = 0;
	int result = mg_receive_frame(fd, MG_OP_UDP_RECEIVE_MSG, &response, &response_size);
	mg_inside--;
	if (nonblocking && (status_flags & O_NONBLOCK)) fcntl(fd, F_SETFL, status_flags);
	if (result < 0) {
		free(response);
		return -1;
	}
	struct sockaddr_storage remote_source;
	socklen_t remote_source_size = 0;
	int consumed = mg_decode_address(response, response_size, &remote_source, &remote_source_size);
	if (consumed < 0 || response_size < (uint32_t)consumed + MG_DATAGRAM_METADATA_SIZE) {
		free(response); errno = EPROTO; return -1;
	}
	if (metadata) memcpy(metadata, response + consumed, MG_DATAGRAM_METADATA_SIZE);
	size_t payload_size = response_size - (size_t)consumed - MG_DATAGRAM_METADATA_SIZE;
	size_t copied = payload_size < count ? payload_size : count;
	memcpy(buffer, response + consumed + MG_DATAGRAM_METADATA_SIZE, copied);
	free(response);
	if (source && source_size) {
		socklen_t destination = *source_size < remote_source_size ? *source_size : remote_source_size;
		memcpy(source, &remote_source, destination);
		*source_size = remote_source_size;
	}
	return ((flags & MSG_TRUNC) && payload_size > count) ? (ssize_t)payload_size : (ssize_t)copied;
}

static int mg_adopt_unconnected_udp(int sockfd) {
	int type = 0;
	socklen_t type_size = sizeof(type);
	if (!getenv("MOGATE_SOCKET") || mg_real_getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0 ||
		type != SOCK_DGRAM) return 0;
	uint32_t udp_options = mg_capture_udp_options(sockfd);
	int status_flags = mg_real_fcntl(sockfd, F_GETFL);
	int descriptor_flags = mg_real_fcntl(sockfd, F_GETFD);
	mg_inside++;
	int proxy = mg_agent_connection();
	int result = proxy < 0 ? -1 : mg_send_frame(proxy, MG_OP_UDP_OPEN_METADATA, NULL, 0);
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	if (result == 0) result = mg_receive_frame(proxy, MG_OP_UDP_OPEN_METADATA, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	free(response);
	if (result == 0) result = mg_real_dup2(proxy, sockfd);
	if (proxy >= 0) mg_real_close(proxy);
	if (result >= 0) {
		if (descriptor_flags >= 0) mg_real_fcntl(sockfd, F_SETFD, descriptor_flags);
		if (status_flags >= 0) mg_real_fcntl(sockfd, F_SETFL, status_flags);
		result = mg_register_descriptor(sockfd, MG_DESCRIPTOR_UDP_UNCONNECTED, NULL, 0);
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(sockfd);
		if (descriptor) descriptor->ancillary_options = udp_options;
	}
	mg_inside--;
	return result < 0 ? -1 : 1;
}

static ssize_t mg_udp_sendto_metadata(int fd, const void *buffer, size_t count,
	const struct sockaddr *destination, socklen_t destination_size,
	const unsigned char metadata[MG_DATAGRAM_METADATA_SIZE]) {
	unsigned char address[MG_ADDRESS_IPV6_SIZE];
	int address_size = mg_encode_address(address, sizeof(address), destination, destination_size);
	if (address_size < 0) return -1;
	if (count > MG_MAX_PAYLOAD - (size_t)address_size - MG_DATAGRAM_METADATA_SIZE)
		count = MG_MAX_PAYLOAD - (size_t)address_size - MG_DATAGRAM_METADATA_SIZE;
	unsigned char *payload = malloc((size_t)address_size + MG_DATAGRAM_METADATA_SIZE + count);
	if (!payload) { errno = ENOMEM; return -1; }
	memcpy(payload, address, (size_t)address_size);
	memcpy(payload + address_size, metadata, MG_DATAGRAM_METADATA_SIZE);
	memcpy(payload + address_size + MG_DATAGRAM_METADATA_SIZE, buffer, count);
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor) { free(payload); errno = EBADF; return -1; }
	pthread_mutex_lock(&descriptor->write_lock);
	mg_inside++;
	int result = mg_send_frame(fd, MG_OP_UDP_SEND_MSG, payload,
		(uint32_t)((size_t)address_size + MG_DATAGRAM_METADATA_SIZE + count));
	mg_inside--;
	pthread_mutex_unlock(&descriptor->write_lock);
	free(payload);
	return result < 0 ? -1 : (ssize_t)count;
}

static ssize_t mg_udp_sendto_unconnected(int fd, const void *buffer, size_t count,
	const struct sockaddr *destination, socklen_t destination_size) {
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE] = {0};
	return mg_udp_sendto_metadata(fd, buffer, count, destination, destination_size, metadata);
}

static ssize_t mg_udp_receive_unconnected(int fd, void *buffer, size_t count, int flags,
	struct sockaddr *source, socklen_t *source_size,
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE]) {
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor) { errno = EBADF; return -1; }
	int status_flags = mg_real_fcntl(fd, F_GETFL);
	int nonblocking = (status_flags >= 0 && (status_flags & O_NONBLOCK)) || (flags & MSG_DONTWAIT);
	pthread_mutex_lock(&descriptor->read_lock);
	if (!descriptor->peek_payload) {
		if (nonblocking) {
			struct pollfd candidate = {.fd = fd, .events = POLLIN};
			int ready = mg_real_poll(&candidate, 1, 0);
			if (ready <= 0 || !(candidate.revents & (POLLIN | POLLHUP))) {
				pthread_mutex_unlock(&descriptor->read_lock); errno = EAGAIN; return -1;
			}
			if (status_flags & O_NONBLOCK) mg_real_fcntl(fd, F_SETFL, status_flags & ~O_NONBLOCK);
		}
		mg_inside++;
		unsigned char *frame = NULL;
		uint32_t frame_size = 0;
		int result = mg_receive_frame(fd, MG_OP_UDP_RECEIVE_MSG, &frame, &frame_size);
		mg_inside--;
		if (nonblocking && (status_flags & O_NONBLOCK)) mg_real_fcntl(fd, F_SETFL, status_flags);
		if (result < 0) {
			free(frame); pthread_mutex_unlock(&descriptor->read_lock); return -1;
		}
		int consumed = mg_decode_address(frame, frame_size, &descriptor->peek_source, &descriptor->peek_source_size);
		if (consumed < 0 || frame_size < (uint32_t)consumed + MG_DATAGRAM_METADATA_SIZE) {
			free(frame); pthread_mutex_unlock(&descriptor->read_lock); return -1;
		}
		memcpy(descriptor->peek_metadata, frame + consumed, MG_DATAGRAM_METADATA_SIZE);
		consumed += MG_DATAGRAM_METADATA_SIZE;
		descriptor->peek_size = frame_size - (uint32_t)consumed;
		descriptor->peek_payload = malloc(descriptor->peek_size ? descriptor->peek_size : 1);
		if (!descriptor->peek_payload) {
			free(frame); pthread_mutex_unlock(&descriptor->read_lock); errno = ENOMEM; return -1;
		}
		memcpy(descriptor->peek_payload, frame + consumed, descriptor->peek_size);
		free(frame);
	}
	if (metadata) memcpy(metadata, descriptor->peek_metadata, MG_DATAGRAM_METADATA_SIZE);
	size_t copied = descriptor->peek_size < count ? descriptor->peek_size : count;
	memcpy(buffer, descriptor->peek_payload, copied);
	if (source && source_size) {
		socklen_t copied_source = *source_size < descriptor->peek_source_size ? *source_size : descriptor->peek_source_size;
		memcpy(source, &descriptor->peek_source, copied_source);
		*source_size = descriptor->peek_source_size;
	}
	ssize_t returned = ((flags & MSG_TRUNC) && descriptor->peek_size > count) ? (ssize_t)descriptor->peek_size : (ssize_t)copied;
	if (!(flags & MSG_PEEK)) {
		free(descriptor->peek_payload);
		descriptor->peek_payload = NULL;
		descriptor->peek_size = 0;
		descriptor->peek_source_size = 0;
	}
	pthread_mutex_unlock(&descriptor->read_lock);
	return returned;
}

static int mg_finalize_tcp(int fd, int block) {
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || descriptor->kind != MG_DESCRIPTOR_TCP_PENDING) return 1;
	if (!block) {
		struct pollfd candidate = {.fd = fd, .events = POLLIN};
		int ready = mg_real_poll(&candidate, 1, 0);
		if (ready <= 0 || !(candidate.revents & (POLLIN | POLLHUP | POLLERR))) return 0;
	}
	pthread_mutex_lock(&descriptor->io_lock);
	if (descriptor->kind != MG_DESCRIPTOR_TCP_PENDING) {
		pthread_mutex_unlock(&descriptor->io_lock);
		return 1;
	}
	int flags = mg_real_fcntl(fd, F_GETFL);
	if (flags >= 0 && (flags & O_NONBLOCK)) mg_real_fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	mg_inside++;
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	int result = mg_receive_frame(fd, MG_OP_TCP_CONNECT, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	int connect_error = result < 0 ? errno : 0;
	free(response);
	mg_inside--;
	if (flags >= 0 && (flags & O_NONBLOCK)) mg_real_fcntl(fd, F_SETFL, flags);
	descriptor->connect_error = connect_error;
	descriptor->error_reported = 0;
	descriptor->kind = connect_error ? MG_DESCRIPTOR_TCP_FAILED : MG_DESCRIPTOR_TCP_CONNECTED;
	pthread_mutex_unlock(&descriptor->io_lock);
	return 1;
}

static int mg_prepare_tcp_io(int fd) {
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || (descriptor->kind != MG_DESCRIPTOR_TCP_PENDING &&
		descriptor->kind != MG_DESCRIPTOR_TCP_FAILED && descriptor->kind != MG_DESCRIPTOR_TCP_CONNECTED)) return 1;
	if (descriptor->kind == MG_DESCRIPTOR_TCP_PENDING) {
		int flags = mg_real_fcntl(fd, F_GETFL);
		int blocking = flags < 0 || !(flags & O_NONBLOCK);
		if (!mg_finalize_tcp(fd, blocking)) { errno = EAGAIN; return 0; }
	}
	if (descriptor->kind == MG_DESCRIPTOR_TCP_FAILED) {
		errno = descriptor->connect_error ? descriptor->connect_error : ENOTCONN;
		return 0;
	}
	return 1;
}

static int mg_poll_hook(struct pollfd *descriptors, nfds_t count, int timeout) {
	if (mg_inside || mg_symbols() < 0) return mg_real_poll ? mg_real_poll(descriptors, count, timeout) : -1;
	struct pollfd *translated = calloc(count ? count : 1, sizeof(*translated));
	if (!translated) { errno = ENOMEM; return -1; }
	for (nfds_t index = 0; index < count; index++) {
		translated[index] = descriptors[index];
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(descriptors[index].fd);
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_PENDING && (descriptors[index].events & POLLOUT)) {
			translated[index].events &= (short)~POLLOUT;
			translated[index].events |= POLLIN;
		}
	}
	int result = mg_real_poll(translated, count, timeout);
	if (result >= 0) {
		int ready_count = 0;
		for (nfds_t index = 0; index < count; index++) {
			descriptors[index].revents = translated[index].revents;
			struct mg_virtual_descriptor *descriptor = mg_descriptor_for(descriptors[index].fd);
			if (descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_PENDING && (descriptors[index].events & POLLOUT)) {
				descriptors[index].revents &= (short)~POLLIN;
				if (translated[index].revents & (POLLIN | POLLHUP | POLLERR)) {
					(void)mg_finalize_tcp(descriptors[index].fd, 0);
					descriptor = mg_descriptor_for(descriptors[index].fd);
					descriptors[index].revents |= POLLOUT;
					if (descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_FAILED) descriptors[index].revents |= POLLERR;
				}
			}
			if (descriptors[index].revents) ready_count++;
		}
		result = ready_count;
	}
	free(translated);
	return result;
}

#ifndef __APPLE__
static struct mg_epoll_watch *mg_epoll_find_locked(int epoll_fd, int fd, uint64_t token) {
	for (struct mg_epoll_watch *watch = mg_epoll_watches; watch; watch = watch->next) {
		if (watch->epoll_fd == epoll_fd &&
			((fd >= 0 && watch->fd == fd) || (token && watch->token == token))) return watch;
	}
	return NULL;
}

static void mg_epoll_remove_locked(struct mg_epoll_watch *watch) {
	struct mg_epoll_watch **cursor = &mg_epoll_watches;
	while (*cursor) {
		if (*cursor == watch) {
			*cursor = watch->next;
			free(watch);
			return;
		}
		cursor = &(*cursor)->next;
	}
}

static int mg_epoll_ctl_hook(int epoll_fd, int operation, int fd, struct epoll_event *event) {
	if (mg_inside || mg_symbols() < 0)
		return mg_real_epoll_ctl ? mg_real_epoll_ctl(epoll_fd, operation, fd, event) : -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	int pending_write = descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_PENDING && event &&
		(operation == EPOLL_CTL_ADD || operation == EPOLL_CTL_MOD) && (event->events & EPOLLOUT);
	if (!pending_write) {
		int result = mg_real_epoll_ctl(epoll_fd, operation, fd, event);
		if (result == 0 && (operation == EPOLL_CTL_MOD || operation == EPOLL_CTL_DEL)) {
			pthread_mutex_lock(&mg_epoll_lock);
			struct mg_epoll_watch *watch = mg_epoll_find_locked(epoll_fd, fd, 0);
			if (watch) mg_epoll_remove_locked(watch);
			pthread_mutex_unlock(&mg_epoll_lock);
		}
		return result;
	}
	struct epoll_event translated = *event;
	translated.events = (translated.events & ~EPOLLOUT) | EPOLLIN;
	pthread_mutex_lock(&mg_epoll_lock);
	struct mg_epoll_watch *watch = mg_epoll_find_locked(epoll_fd, fd, 0);
	int created = 0;
	if (!watch) {
		watch = calloc(1, sizeof(*watch));
		if (!watch) { pthread_mutex_unlock(&mg_epoll_lock); errno = ENOMEM; return -1; }
		watch->epoll_fd = epoll_fd;
		watch->fd = fd;
		watch->token = mg_epoll_token++;
		if (!watch->token) watch->token = mg_epoll_token++;
		watch->next = mg_epoll_watches;
		mg_epoll_watches = watch;
		created = 1;
	}
	watch->original = *event;
	translated.data.u64 = watch->token;
	int result = mg_real_epoll_ctl(epoll_fd, operation, fd, &translated);
	if (result < 0 && created) mg_epoll_remove_locked(watch);
	pthread_mutex_unlock(&mg_epoll_lock);
	return result;
}

static int mg_epoll_wait_common(int epoll_fd, struct epoll_event *events, int maximum,
	int timeout, const sigset_t *mask) {
	if (mg_inside || mg_symbols() < 0) {
		if (mask && mg_real_epoll_pwait) return mg_real_epoll_pwait(epoll_fd, events, maximum, timeout, mask);
		return mg_real_epoll_wait ? mg_real_epoll_wait(epoll_fd, events, maximum, timeout) : -1;
	}
	int result = mask ? mg_real_epoll_pwait(epoll_fd, events, maximum, timeout, mask) :
		mg_real_epoll_wait(epoll_fd, events, maximum, timeout);
	if (result <= 0) return result;
	for (int index = 0; index < result; index++) {
		pthread_mutex_lock(&mg_epoll_lock);
		struct mg_epoll_watch *watch = mg_epoll_find_locked(epoll_fd, -1, events[index].data.u64);
		if (!watch) { pthread_mutex_unlock(&mg_epoll_lock); continue; }
		int fd = watch->fd;
		struct epoll_event original = watch->original;
		mg_epoll_remove_locked(watch);
		pthread_mutex_unlock(&mg_epoll_lock);
		(void)mg_finalize_tcp(fd, 0);
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
		events[index].data = original.data;
		events[index].events = EPOLLOUT;
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_FAILED) events[index].events |= EPOLLERR;
		if (!(original.events & EPOLLONESHOT)) (void)mg_real_epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &original);
	}
	return result;
}

static int mg_epoll_wait_hook(int epoll_fd, struct epoll_event *events, int maximum, int timeout) {
	return mg_epoll_wait_common(epoll_fd, events, maximum, timeout, NULL);
}

static int mg_epoll_pwait_hook(int epoll_fd, struct epoll_event *events, int maximum,
	int timeout, const sigset_t *mask) {
	return mg_epoll_wait_common(epoll_fd, events, maximum, timeout, mask);
}

static void mg_drop_readiness_watches(int fd) {
	pthread_mutex_lock(&mg_epoll_lock);
	struct mg_epoll_watch **cursor = &mg_epoll_watches;
	while (*cursor) {
		if ((*cursor)->epoll_fd == fd || (*cursor)->fd == fd) {
			struct mg_epoll_watch *removed = *cursor;
			*cursor = removed->next;
			free(removed);
		} else {
			cursor = &(*cursor)->next;
		}
	}
	pthread_mutex_unlock(&mg_epoll_lock);
}
#else
static struct mg_kqueue_watch *mg_kqueue_find_locked(int queue_fd, uintptr_t ident, uint64_t token) {
	for (struct mg_kqueue_watch *watch = mg_kqueue_watches; watch; watch = watch->next) {
		if (watch->queue_fd == queue_fd &&
			((ident != (uintptr_t)-1 && watch->ident == ident) || (token && watch->token == token))) return watch;
	}
	return NULL;
}

static void mg_kqueue_remove_locked(struct mg_kqueue_watch *watch) {
	struct mg_kqueue_watch **cursor = &mg_kqueue_watches;
	while (*cursor) {
		if (*cursor == watch) { *cursor = watch->next; free(watch); return; }
		cursor = &(*cursor)->next;
	}
}

static int mg_kevent_hook(int queue_fd, const struct kevent *changes, int change_count,
	struct kevent *events, int event_count, const struct timespec *timeout) {
	if (mg_inside || mg_symbols() < 0)
		return mg_real_kevent ? mg_real_kevent(queue_fd, changes, change_count, events, event_count, timeout) : -1;
	struct kevent *translated = NULL;
	if (change_count > 0) {
		translated = malloc((size_t)change_count * sizeof(*translated));
		if (!translated) { errno = ENOMEM; return -1; }
		memcpy(translated, changes, (size_t)change_count * sizeof(*translated));
		pthread_mutex_lock(&mg_kqueue_lock);
		for (int index = 0; index < change_count; index++) {
			struct mg_kqueue_watch *old = mg_kqueue_find_locked(queue_fd, changes[index].ident, 0);
			if ((changes[index].flags & EV_DELETE) && old) mg_kqueue_remove_locked(old);
			struct mg_virtual_descriptor *descriptor = mg_descriptor_for((int)changes[index].ident);
			if (changes[index].filter != EVFILT_WRITE || !(changes[index].flags & EV_ADD) ||
				!descriptor || descriptor->kind != MG_DESCRIPTOR_TCP_PENDING) continue;
			struct mg_kqueue_watch *watch = old;
			if (!watch) {
				watch = calloc(1, sizeof(*watch));
				if (!watch) { pthread_mutex_unlock(&mg_kqueue_lock); free(translated); errno = ENOMEM; return -1; }
				watch->queue_fd = queue_fd;
				watch->ident = changes[index].ident;
				watch->token = mg_kqueue_token++;
				if (!watch->token) watch->token = mg_kqueue_token++;
				watch->next = mg_kqueue_watches;
				mg_kqueue_watches = watch;
			}
			watch->original = changes[index];
			translated[index].filter = EVFILT_READ;
			translated[index].udata = (void *)(uintptr_t)watch->token;
		}
		pthread_mutex_unlock(&mg_kqueue_lock);
	}
	int result = mg_real_kevent(queue_fd, translated ? translated : changes, change_count,
		events, event_count, timeout);
	free(translated);
	if (result <= 0) return result;
	for (int index = 0; index < result; index++) {
		uint64_t token = (uint64_t)(uintptr_t)events[index].udata;
		pthread_mutex_lock(&mg_kqueue_lock);
		struct mg_kqueue_watch *watch = mg_kqueue_find_locked(queue_fd, (uintptr_t)-1, token);
		if (!watch) { pthread_mutex_unlock(&mg_kqueue_lock); continue; }
		int fd = (int)watch->ident;
		struct kevent original = watch->original;
		mg_kqueue_remove_locked(watch);
		pthread_mutex_unlock(&mg_kqueue_lock);
		(void)mg_finalize_tcp(fd, 0);
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
		events[index].ident = original.ident;
		events[index].filter = EVFILT_WRITE;
		events[index].udata = original.udata;
		events[index].flags &= (EV_EOF | EV_ERROR);
		events[index].fflags = 0;
		events[index].data = 0;
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_TCP_FAILED) {
			events[index].flags |= EV_EOF;
			events[index].fflags = (uint32_t)descriptor->connect_error;
		}
		if (!(original.flags & EV_ONESHOT)) (void)mg_real_kevent(queue_fd, &original, 1, NULL, 0, NULL);
	}
	return result;
}

static void mg_drop_readiness_watches(int fd) {
	pthread_mutex_lock(&mg_kqueue_lock);
	struct mg_kqueue_watch **cursor = &mg_kqueue_watches;
	while (*cursor) {
		if ((*cursor)->queue_fd == fd || (*cursor)->ident == (uintptr_t)fd) {
			struct mg_kqueue_watch *removed = *cursor;
			*cursor = removed->next;
			free(removed);
		} else {
			cursor = &(*cursor)->next;
		}
	}
	pthread_mutex_unlock(&mg_kqueue_lock);
}
#endif

static int mg_select_hook(int descriptor_count, fd_set *read_set, fd_set *write_set,
	fd_set *error_set, struct timeval *timeout) {
	if (mg_inside || mg_symbols() < 0)
		return mg_real_select ? mg_real_select(descriptor_count, read_set, write_set, error_set, timeout) : -1;
	if (descriptor_count < 0 || descriptor_count > FD_SETSIZE) { errno = EINVAL; return -1; }
	struct pollfd *descriptors = calloc(descriptor_count ? (size_t)descriptor_count : 1, sizeof(*descriptors));
	if (!descriptors) { errno = ENOMEM; return -1; }
	nfds_t used = 0;
	for (int fd = 0; fd < descriptor_count; fd++) {
		short events = 0;
		if (read_set && FD_ISSET(fd, read_set)) events |= POLLIN;
		if (write_set && FD_ISSET(fd, write_set)) events |= POLLOUT;
		if (error_set && FD_ISSET(fd, error_set)) events |= POLLPRI;
		if (events) descriptors[used++] = (struct pollfd){.fd = fd, .events = events};
	}
	int milliseconds = -1;
	if (timeout) {
		long long value = (long long)timeout->tv_sec * 1000LL + (timeout->tv_usec + 999) / 1000;
		milliseconds = value > 2147483647LL ? 2147483647 : (int)value;
	}
	int result = mg_poll_hook(descriptors, used, milliseconds);
	if (result >= 0) {
		if (read_set) FD_ZERO(read_set);
		if (write_set) FD_ZERO(write_set);
		if (error_set) FD_ZERO(error_set);
		int ready = 0;
		for (nfds_t index = 0; index < used; index++) {
			int fd_ready = 0;
			if (read_set && (descriptors[index].revents & (POLLIN | POLLHUP))) { FD_SET(descriptors[index].fd, read_set); fd_ready = 1; }
			if (write_set && (descriptors[index].revents & POLLOUT)) { FD_SET(descriptors[index].fd, write_set); fd_ready = 1; }
			if (error_set && (descriptors[index].revents & (POLLERR | POLLPRI | POLLNVAL))) { FD_SET(descriptors[index].fd, error_set); fd_ready = 1; }
			if (fd_ready) ready++;
		}
		result = ready;
	}
	free(descriptors);
	return result;
}

static int mg_getsockopt_hook(int fd, int level, int option, void *value, socklen_t *size) {
	if (mg_inside || mg_symbols() < 0) return mg_real_getsockopt ? mg_real_getsockopt(fd, level, option, value, size) : -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor) return mg_real_getsockopt(fd, level, option, value, size);
	if (level == SOL_SOCKET && option == SO_TYPE && value && size && *size >= sizeof(int)) {
		*(int *)value = (descriptor->kind == MG_DESCRIPTOR_UDP_CONNECTED || descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED) ? SOCK_DGRAM : SOCK_STREAM;
		*size = sizeof(int); return 0;
	}
	if (level == SOL_SOCKET && option == SO_ERROR && value && size && *size >= sizeof(int)) {
		if (descriptor->kind == MG_DESCRIPTOR_TCP_PENDING && !mg_finalize_tcp(fd, 0)) {
			*(int *)value = EINPROGRESS;
		} else if (descriptor->kind == MG_DESCRIPTOR_TCP_FAILED && !descriptor->error_reported) {
			*(int *)value = descriptor->connect_error;
			descriptor->error_reported = 1;
		} else {
			*(int *)value = 0;
		}
		*size = sizeof(int); return 0;
	}
	return mg_real_getsockopt(fd, level, option, value, size);
}

static int mg_setsockopt_hook(int fd, int level, int option, const void *value, socklen_t size) {
	if (mg_inside || mg_symbols() < 0)
		return mg_real_setsockopt ? mg_real_setsockopt(fd, level, option, value, size) : -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	uint32_t bit = mg_udp_option_bit(level, option);
	if (!descriptor || !bit || (descriptor->kind != MG_DESCRIPTOR_UDP_CONNECTED &&
		descriptor->kind != MG_DESCRIPTOR_UDP_UNCONNECTED)) {
		return mg_real_setsockopt(fd, level, option, value, size);
	}
	if (!value || size < sizeof(int)) { errno = EINVAL; return -1; }
	pthread_mutex_lock(&descriptor->io_lock);
	if (*(const int *)value) descriptor->ancillary_options |= bit;
	else descriptor->ancillary_options &= ~bit;
	pthread_mutex_unlock(&descriptor->io_lock);
	return 0;
}

static ssize_t mg_send_hook(int fd, const void *buffer, size_t count, int flags) {
	if (mg_inside) {
		if (mg_real_send) return mg_real_send(fd, buffer, count, flags);
		errno = ENOSYS; return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (!mg_prepare_tcp_io(fd)) return -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || (descriptor->kind != MG_DESCRIPTOR_UDP_CONNECTED && descriptor->kind != MG_DESCRIPTOR_UDP_UNCONNECTED))
		return mg_real_send(fd, buffer, count, flags);
	if (descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED) {
		if (!descriptor->peer_size) { errno = EDESTADDRREQ; return -1; }
		return mg_udp_sendto_unconnected(fd, buffer, count, (struct sockaddr *)&descriptor->peer, descriptor->peer_size);
	}
	return mg_udp_send_hook(fd, buffer, count);
}

static ssize_t mg_recv_hook(int fd, void *buffer, size_t count, int flags) {
	if (mg_inside) {
		if (mg_real_recv) return mg_real_recv(fd, buffer, count, flags);
		errno = ENOSYS; return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (!mg_prepare_tcp_io(fd)) return -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || (descriptor->kind != MG_DESCRIPTOR_UDP_CONNECTED && descriptor->kind != MG_DESCRIPTOR_UDP_UNCONNECTED))
		return mg_real_recv(fd, buffer, count, flags);
	if (descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED)
		return mg_udp_receive_unconnected(fd, buffer, count, flags, NULL, NULL, NULL);
	return mg_udp_receive_hook(fd, buffer, count, flags, NULL, NULL, NULL);
}

static ssize_t mg_sendto_hook(int fd, const void *buffer, size_t count, int flags,
	const struct sockaddr *destination, socklen_t destination_size) {
	if (mg_inside) {
		if (mg_real_sendto) return mg_real_sendto(fd, buffer, count, flags, destination, destination_size);
		errno = ENOSYS; return -1;
	}
	if (mg_symbols() < 0) return -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor) {
		if (!destination || (destination->sa_family != AF_INET && destination->sa_family != AF_INET6))
			return mg_real_sendto(fd, buffer, count, flags, destination, destination_size);
		int adopted = mg_adopt_unconnected_udp(fd);
		if (adopted < 0) return -1;
		if (adopted == 0) return mg_real_sendto(fd, buffer, count, flags, destination, destination_size);
		descriptor = mg_descriptor_for(fd);
	}
	if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED)
		return mg_udp_sendto_unconnected(fd, buffer, count, destination, destination_size);
	return mg_udp_send_hook(fd, buffer, count);
}

static ssize_t mg_recvfrom_hook(int fd, void *buffer, size_t count, int flags,
	struct sockaddr *source, socklen_t *source_size) {
	if (mg_inside) {
		if (mg_real_recvfrom) return mg_real_recvfrom(fd, buffer, count, flags, source, source_size);
		errno = ENOSYS; return -1;
	}
	if (mg_symbols() < 0) return -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || (descriptor->kind != MG_DESCRIPTOR_UDP_CONNECTED && descriptor->kind != MG_DESCRIPTOR_UDP_UNCONNECTED))
		return mg_real_recvfrom(fd, buffer, count, flags, source, source_size);
	if (descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED)
		return mg_udp_receive_unconnected(fd, buffer, count, flags, source, source_size, NULL);
	return mg_udp_receive_hook(fd, buffer, count, flags, source, source_size, NULL);
}

static size_t mg_iov_size(const struct iovec *vectors, size_t count) {
	size_t total = 0;
	for (size_t index = 0; index < count; index++) {
		if (vectors[index].iov_len > MG_MAX_PAYLOAD - total) return MG_MAX_PAYLOAD;
		total += vectors[index].iov_len;
	}
	return total;
}

static ssize_t mg_sendmsg_hook(int fd, const struct msghdr *message, int flags) {
	if (mg_inside || mg_symbols() < 0) return mg_real_sendmsg ? mg_real_sendmsg(fd, message, flags) : -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	const struct sockaddr *destination = message ? (const struct sockaddr *)message->msg_name : NULL;
	int remote_candidate = descriptor != NULL || (destination && getenv("MOGATE_SOCKET") &&
		(destination->sa_family == AF_INET || destination->sa_family == AF_INET6));
	if (!remote_candidate) return mg_real_sendmsg(fd, message, flags);
	if (!message) { errno = EINVAL; return -1; }
	int remote_udp = descriptor && (descriptor->kind == MG_DESCRIPTOR_UDP_CONNECTED ||
		descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED);
	if (descriptor && !remote_udp) {
		if (message->msg_controllen) { errno = ENOTSUP; return -1; }
	}
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE];
	if (mg_encode_datagram_metadata(metadata, message) < 0) return -1;
	size_t total = mg_iov_size(message->msg_iov, message->msg_iovlen);
	unsigned char *payload = malloc(total ? total : 1);
	if (!payload) { errno = ENOMEM; return -1; }
	size_t offset = 0;
	for (size_t index = 0; index < message->msg_iovlen && offset < total; index++) {
		size_t part = message->msg_iov[index].iov_len;
		if (part > total - offset) part = total - offset;
		memcpy(payload + offset, message->msg_iov[index].iov_base, part);
		offset += part;
	}
	ssize_t result;
	if (descriptor && !remote_udp) {
		result = mg_send_hook(fd, payload, total, flags);
	} else if (!descriptor) {
		int adopted = mg_adopt_unconnected_udp(fd);
		if (adopted <= 0) { free(payload); return adopted < 0 ? -1 : mg_real_sendmsg(fd, message, flags); }
		descriptor = mg_descriptor_for(fd);
		if (message->msg_name)
			result = mg_udp_sendto_metadata(fd, payload, total, message->msg_name, message->msg_namelen, metadata);
		else { free(payload); errno = EDESTADDRREQ; return -1; }
	} else if (message->msg_name) {
		result = mg_udp_sendto_metadata(fd, payload, total, message->msg_name, message->msg_namelen, metadata);
	} else if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED) {
		if (!descriptor->peer_size) { free(payload); errno = EDESTADDRREQ; return -1; }
		result = mg_udp_sendto_metadata(fd, payload, total, (struct sockaddr *)&descriptor->peer, descriptor->peer_size, metadata);
	} else {
		result = mg_udp_send_metadata(fd, payload, total, metadata);
	}
	free(payload);
	return result;
}

static ssize_t mg_recvmsg_hook(int fd, struct msghdr *message, int flags) {
	if (mg_inside || mg_symbols() < 0) return mg_real_recvmsg ? mg_real_recvmsg(fd, message, flags) : -1;
	struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
	if (!descriptor || (descriptor->kind != MG_DESCRIPTOR_UDP_CONNECTED && descriptor->kind != MG_DESCRIPTOR_UDP_UNCONNECTED))
		return mg_real_recvmsg(fd, message, flags);
	if (!message) { errno = EINVAL; return -1; }
	size_t total = mg_iov_size(message->msg_iov, message->msg_iovlen);
	unsigned char *payload = malloc(total ? total : 1);
	if (!payload) { errno = ENOMEM; return -1; }
	unsigned char metadata[MG_DATAGRAM_METADATA_SIZE] = {0};
	ssize_t received;
	if (descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED)
		received = mg_udp_receive_unconnected(fd, payload, total, flags,
			message->msg_name, message->msg_name ? &message->msg_namelen : NULL, metadata);
	else
		received = mg_udp_receive_hook(fd, payload, total, flags,
			message->msg_name, message->msg_name ? &message->msg_namelen : NULL, metadata);
	if (received >= 0) {
		size_t available = (size_t)received < total ? (size_t)received : total;
		size_t offset = 0;
		for (size_t index = 0; index < message->msg_iovlen && offset < available; index++) {
			size_t part = message->msg_iov[index].iov_len;
			if (part > available - offset) part = available - offset;
			memcpy(message->msg_iov[index].iov_base, payload + offset, part);
			offset += part;
		}
		message->msg_flags = ((size_t)received > total) ? MSG_TRUNC : 0;
		mg_decode_datagram_metadata(metadata, descriptor->ancillary_options, message);
	}
	free(payload);
	return received;
}

static ssize_t mg_read_hook(int fd, void *buffer, size_t count) {
	if (mg_inside) {
		if (mg_real_read) return mg_real_read(fd, buffer, count);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (!mg_prepare_tcp_io(fd)) return -1;
	if (!mg_is_remote_file(fd)) {
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED)
			return mg_udp_receive_unconnected(fd, buffer, count, 0, NULL, NULL, NULL);
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_CONNECTED)
			return mg_udp_receive_hook(fd, buffer, count, 0, NULL, NULL, NULL);
		return mg_real_read(fd, buffer, count);
	}
	struct mg_virtual_descriptor *file_descriptor = mg_descriptor_for(fd);
	if (!file_descriptor) { errno = EBADF; return -1; }
	pthread_mutex_lock(&file_descriptor->io_lock);
	if (count > MG_MAX_PAYLOAD - 4) count = MG_MAX_PAYLOAD - 4;
	unsigned char request[4];
	mg_put_u32(request, (uint32_t)count);
	mg_inside++;
	if (mg_send_frame(fd, MG_OP_FILE_READ, request, sizeof(request)) < 0) {
		mg_inside--;
		pthread_mutex_unlock(&file_descriptor->io_lock);
		return -1;
	}
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	int result = mg_receive_frame(fd, MG_OP_FILE_READ, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	if (result == 0) {
		if (data_size > count) {
			errno = EPROTO;
			result = -1;
		} else {
			memcpy(buffer, data, data_size);
			result = (int)data_size;
		}
	}
	free(response);
	mg_inside--;
	pthread_mutex_unlock(&file_descriptor->io_lock);
	return result;
}

static ssize_t mg_write_hook(int fd, const void *buffer, size_t count) {
	if (mg_inside) {
		if (mg_real_write) return mg_real_write(fd, buffer, count);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (!mg_prepare_tcp_io(fd)) return -1;
	if (!mg_is_remote_file(fd)) {
		struct mg_virtual_descriptor *descriptor = mg_descriptor_for(fd);
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_UNCONNECTED) {
			if (!descriptor->peer_size) { errno = EDESTADDRREQ; return -1; }
			return mg_udp_sendto_unconnected(fd, buffer, count, (struct sockaddr *)&descriptor->peer, descriptor->peer_size);
		}
		if (descriptor && descriptor->kind == MG_DESCRIPTOR_UDP_CONNECTED)
			return mg_udp_send_hook(fd, buffer, count);
		return mg_real_write(fd, buffer, count);
	}
	struct mg_virtual_descriptor *file_descriptor = mg_descriptor_for(fd);
	if (!file_descriptor) { errno = EBADF; return -1; }
	pthread_mutex_lock(&file_descriptor->io_lock);
	if (count > MG_MAX_PAYLOAD) count = MG_MAX_PAYLOAD;
	mg_inside++;
	if (mg_send_frame(fd, MG_OP_FILE_WRITE, buffer, (uint32_t)count) < 0) {
		mg_inside--;
		pthread_mutex_unlock(&file_descriptor->io_lock);
		return -1;
	}
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	int result = mg_receive_frame(fd, MG_OP_FILE_WRITE, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	if (result == 0 && data_size == 4) result = (int)mg_get_u32(data);
	else if (result == 0) { errno = EPROTO; result = -1; }
	free(response);
	mg_inside--;
	pthread_mutex_unlock(&file_descriptor->io_lock);
	return result;
}

static off_t mg_lseek_hook(int fd, off_t offset, int whence) {
	if (mg_inside) {
		if (mg_real_lseek) return mg_real_lseek(fd, offset, whence);
		errno = ENOSYS;
		return (off_t)-1;
	}
	if (mg_symbols() < 0) return (off_t)-1;
	if (!mg_is_remote_file(fd)) return mg_real_lseek(fd, offset, whence);
	struct mg_virtual_descriptor *file_descriptor = mg_descriptor_for(fd);
	if (!file_descriptor) { errno = EBADF; return (off_t)-1; }
	pthread_mutex_lock(&file_descriptor->io_lock);
	unsigned char request[12];
	mg_put_u64(request, (uint64_t)offset);
	mg_put_u32(request + 8, (uint32_t)whence);
	mg_inside++;
	int result = mg_send_frame(fd, MG_OP_FILE_SEEK, request, sizeof(request));
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	if (result == 0) result = mg_receive_frame(fd, MG_OP_FILE_SEEK, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	off_t position = (off_t)-1;
	if (result == 0 && data_size == 8) position = (off_t)mg_get_u64(data);
	else if (result == 0) errno = EPROTO;
	free(response);
	mg_inside--;
	pthread_mutex_unlock(&file_descriptor->io_lock);
	return position;
}

static int mg_fstat_hook(int fd, struct stat *stat_buffer) {
	if (mg_inside) {
		if (mg_real_fstat) return mg_real_fstat(fd, stat_buffer);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	if (!mg_is_remote_file(fd)) return mg_real_fstat(fd, stat_buffer);
	struct mg_virtual_descriptor *file_descriptor = mg_descriptor_for(fd);
	if (!file_descriptor) { errno = EBADF; return -1; }
	pthread_mutex_lock(&file_descriptor->io_lock);
	mg_inside++;
	int result = mg_send_frame(fd, MG_OP_FILE_STAT, NULL, 0);
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	if (result == 0) result = mg_receive_frame(fd, MG_OP_FILE_STAT, &response, &response_size);
	if (result == 0) result = mg_status(response, response_size, &data, &data_size);
	if (result == 0 && data_size == 24) {
		memset(stat_buffer, 0, sizeof(*stat_buffer));
		stat_buffer->st_mode = (mode_t)mg_get_u32(data);
		stat_buffer->st_size = (off_t)mg_get_u64(data + 8);
		int64_t nanoseconds = (int64_t)mg_get_u64(data + 16);
#ifdef __APPLE__
		stat_buffer->st_mtimespec.tv_sec = nanoseconds / 1000000000LL;
		stat_buffer->st_mtimespec.tv_nsec = nanoseconds % 1000000000LL;
#else
		stat_buffer->st_mtim.tv_sec = nanoseconds / 1000000000LL;
		stat_buffer->st_mtim.tv_nsec = nanoseconds % 1000000000LL;
#endif
	} else if (result == 0) {
		errno = EPROTO;
		result = -1;
	}
	free(response);
	mg_inside--;
	pthread_mutex_unlock(&file_descriptor->io_lock);
	return result;
}

static int mg_close_hook(int fd) {
#ifdef __APPLE__
	if (!mg_ready) return mg_raw_close(fd);
#endif
	if (mg_inside) {
		if (mg_real_close) return mg_real_close(fd);
		errno = ENOSYS;
		return -1;
	}
	if (mg_symbols() < 0) return -1;
	mg_drop_readiness_watches(fd);
	struct mg_virtual_descriptor *known = mg_descriptor_for(fd);
	if (!known) return mg_real_close(fd);
	int last = 0;
	struct mg_virtual_descriptor *descriptor = mg_detach_descriptor(fd, &last);
	if (!descriptor) return mg_real_close(fd);
	if (!last || descriptor->kind != MG_DESCRIPTOR_FILE) {
		int close_result = mg_real_close(fd);
		if (last) mg_free_descriptor(descriptor);
		return close_result;
	}
	mg_inside++;
	int result = mg_send_frame(fd, MG_OP_FILE_CLOSE, NULL, 0);
	if (result == 0) {
		unsigned char *response = NULL, *data = NULL;
		uint32_t response_size = 0, data_size = 0;
		result = mg_receive_frame(fd, MG_OP_FILE_CLOSE, &response, &response_size);
		if (result == 0) result = mg_status(response, response_size, &data, &data_size);
		free(response);
	}
	int saved = errno;
	int close_result = mg_real_close(fd);
	mg_inside--;
	mg_free_descriptor(descriptor);
	if (result < 0) { errno = saved; return -1; }
	return close_result;
}

static void mg_release_replaced_descriptor(int fd, int transport_fd) {
	int last = 0;
	struct mg_virtual_descriptor *descriptor = mg_detach_descriptor(fd, &last);
	if (!descriptor) return;
	if (last && descriptor->kind == MG_DESCRIPTOR_FILE && transport_fd >= 0) {
		mg_inside++;
		if (mg_send_frame(transport_fd, MG_OP_FILE_CLOSE, NULL, 0) == 0) {
			unsigned char *response = NULL;
			uint32_t response_size = 0;
			(void)mg_receive_frame(transport_fd, MG_OP_FILE_CLOSE, &response, &response_size);
			free(response);
		}
		mg_inside--;
	}
	if (last) mg_free_descriptor(descriptor);
}

static int mg_dup_hook(int oldfd) {
	if (mg_symbols() < 0) return -1;
	int result = mg_real_dup(oldfd);
	if (result >= 0 && mg_clone_descriptor(oldfd, result) < 0) {
		int saved = errno; mg_real_close(result); errno = saved; return -1;
	}
	return result;
}

static int mg_dup2_hook(int oldfd, int newfd) {
	if (mg_symbols() < 0) return -1;
	if (oldfd == newfd) return mg_real_dup2(oldfd, newfd);
	int replacement = mg_descriptor_for(newfd) ? mg_real_dup(newfd) : -1;
	int result = mg_real_dup2(oldfd, newfd);
	if (result < 0) {
		if (replacement >= 0) mg_real_close(replacement);
		return -1;
	}
	mg_release_replaced_descriptor(newfd, replacement);
	if (replacement >= 0) mg_real_close(replacement);
	if (mg_clone_descriptor(oldfd, newfd) < 0) {
		int saved = errno; mg_real_close(newfd); errno = saved; return -1;
	}
	return result;
}

#ifndef __APPLE__
static int mg_dup3_hook(int oldfd, int newfd, int flags) {
	if (mg_symbols() < 0) return -1;
	int replacement = mg_descriptor_for(newfd) ? mg_real_dup(newfd) : -1;
	int result = mg_real_dup3(oldfd, newfd, flags);
	if (result < 0) {
		if (replacement >= 0) mg_real_close(replacement);
		return -1;
	}
	mg_release_replaced_descriptor(newfd, replacement);
	if (replacement >= 0) mg_real_close(replacement);
	if (mg_clone_descriptor(oldfd, newfd) < 0) {
		int saved = errno; mg_real_close(newfd); errno = saved; return -1;
	}
	return result;
}
#endif

static int mg_fcntl_hook(int fd, int command, ...) {
	va_list raw_args;
	va_start(raw_args, command);
	void *raw_argument = NULL;
	if (command != F_GETFD && command != F_GETFL) raw_argument = va_arg(raw_args, void *);
	va_end(raw_args);
	if (!mg_ready || mg_inside) {
#ifdef SYS_fcntl
		return (int)syscall(SYS_fcntl, fd, command, raw_argument);
#else
		if (!mg_real_fcntl) { errno = ENOSYS; return -1; }
		return mg_real_fcntl(fd, command, raw_argument);
#endif
	}
	if (mg_symbols() < 0) return -1;
	va_list args;
	va_start(args, command);
	int result;
	switch (command) {
	case F_GETFD:
	case F_GETFL:
		result = mg_real_fcntl(fd, command);
		break;
	case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
#endif
	case F_SETFD:
	case F_SETFL: {
		int argument = (int)(intptr_t)raw_argument;
		result = mg_real_fcntl(fd, command, argument);
		break;
	}
	default: {
		result = mg_real_fcntl(fd, command, raw_argument);
		break;
	}
	}
	va_end(args);
	if (result >= 0 && (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
		|| command == F_DUPFD_CLOEXEC
#endif
	)) {
		if (mg_clone_descriptor(fd, result) < 0) {
			int saved = errno; mg_real_close(result); errno = saved; return -1;
		}
	}
	return result;
}

static void mg_free_owned_addrinfo(struct addrinfo *head) {
	while (head) {
		struct addrinfo *next = head->ai_next;
		free(head->ai_addr);
		free(head->ai_canonname);
		free(head);
		head = next;
	}
}

static int mg_track_dns(struct addrinfo *head, int add) {
	int found = 0;
	pthread_mutex_lock(&mg_dns_lock);
	for (int index = 0; index < MG_MAX_DNS_RESULTS; index++) {
		if (add && !mg_dns_heads[index]) { mg_dns_heads[index] = head; found = 1; break; }
		if (!add && mg_dns_heads[index] == head) { mg_dns_heads[index] = NULL; found = 1; break; }
	}
	pthread_mutex_unlock(&mg_dns_lock);
	return found;
}

static int mg_getaddrinfo_hook(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **result) {
	if (mg_inside) {
		if (mg_real_getaddrinfo) return mg_real_getaddrinfo(node, service, hints, result);
		return EAI_SYSTEM;
	}
	if (mg_symbols() < 0) return EAI_SYSTEM;
	if (!getenv("MOGATE_SOCKET") || !node || !result ||
		(hints && (hints->ai_flags & AI_NUMERICHOST))) {
		return mg_real_getaddrinfo(node, service, hints, result);
	}
	char *end = NULL;
	long port = service ? strtol(service, &end, 10) : 0;
	if (service && (!end || *end || port < 0 || port > 65535)) {
		return mg_real_getaddrinfo(node, service, hints, result);
	}
	mg_inside++;
	int fd = mg_agent_connection();
	if (fd < 0 || mg_send_frame(fd, MG_OP_DNS_LOOKUP, node, (uint32_t)strlen(node)) < 0) {
		if (fd >= 0) mg_real_close(fd);
		mg_inside--;
		return EAI_SYSTEM;
	}
	unsigned char *response = NULL, *data = NULL;
	uint32_t response_size = 0, data_size = 0;
	int call_result = mg_receive_frame(fd, MG_OP_DNS_LOOKUP, &response, &response_size);
	if (call_result == 0) call_result = mg_status(response, response_size, &data, &data_size);
	mg_real_close(fd);
	if (call_result < 0) {
		free(response);
		mg_inside--;
		return EAI_FAIL;
	}
	struct addrinfo *head = NULL, **tail = &head;
	char *cursor = (char *)data;
	char *limit = (char *)data + data_size;
	while (cursor < limit) {
		char *newline = memchr(cursor, '\n', (size_t)(limit - cursor));
		char *line_end = newline ? newline : limit;
		char saved = *line_end;
		*line_end = 0;
		int family = strchr(cursor, ':') ? AF_INET6 : AF_INET;
		if (!hints || hints->ai_family == AF_UNSPEC || hints->ai_family == family) {
			struct addrinfo *item = (struct addrinfo *)calloc(1, sizeof(*item));
			size_t address_size = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
			item->ai_addr = (struct sockaddr *)calloc(1, address_size);
			if (!item || !item->ai_addr) {
				free(item);
				mg_free_owned_addrinfo(head);
				free(response);
				mg_inside--;
				return EAI_MEMORY;
			}
			item->ai_family = family;
			item->ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
			item->ai_protocol = hints ? hints->ai_protocol : 0;
			item->ai_addrlen = (socklen_t)address_size;
			if (family == AF_INET) {
				struct sockaddr_in *address = (struct sockaddr_in *)item->ai_addr;
				address->sin_family = AF_INET; address->sin_port = htons((uint16_t)port);
				inet_pton(AF_INET, cursor, &address->sin_addr);
			} else {
				struct sockaddr_in6 *address = (struct sockaddr_in6 *)item->ai_addr;
				address->sin6_family = AF_INET6; address->sin6_port = htons((uint16_t)port);
				inet_pton(AF_INET6, cursor, &address->sin6_addr);
			}
			*tail = item;
			tail = &item->ai_next;
		}
		*line_end = saved;
		cursor = newline ? newline + 1 : limit;
	}
	free(response);
	if (!head) { mg_inside--; return EAI_NONAME; }
	if (!mg_track_dns(head, 1)) {
		mg_free_owned_addrinfo(head);
		mg_inside--;
		return EAI_MEMORY;
	}
	*result = head;
	mg_inside--;
	return 0;
}

static void mg_freeaddrinfo_hook(struct addrinfo *result) {
	if (mg_inside) {
		if (mg_real_freeaddrinfo) mg_real_freeaddrinfo(result);
		return;
	}
	if (mg_symbols() < 0) return;
	if (result && mg_track_dns(result, 0)) mg_free_owned_addrinfo(result);
	else mg_real_freeaddrinfo(result);
}

#ifdef __APPLE__
// D1: exec-family interpose hooks (darwin only; exec is not SIP-hooked on linux).
// Each is a thin wrapper that resolves the real libSystem exec symbol (past our
// interposers) and hands the substantive work to the tested static detours in
// sip_darwin.h. They no-op (pass straight through to the real call) when the
// injector is inactive (MOGATE_SOCKET unset) or already inside an injector
// operation (mg_inside).

static const char *mg_self_or_null(void) {
	return mg_self_path[0] ? mg_self_path : NULL;
}

static int mg_execve_hook(const char *path, char *const argv[], char *const envp[]) {
	mg_sip_execve_fn real = mg_real_execve;
	if (!real) { errno = ENOSYS; return -1; }
	if (mg_inside || !getenv("MOGATE_SOCKET")) return real(path, argv, envp);
	// Bracket the detour with mg_inside so the patch it performs (reading the
	// binary, writing the cache, spawning codesign) re-enters our file/exec hooks
	// as pass-throughs to the real calls, like every other hook in this file. The
	// detour communicates failure via errno, so preserve it across the decrement.
	mg_inside++;
	int rc = mg_sip_execve_detour(path, argv, envp, mg_self_or_null(), getenv("MOGATE_SOCKET"), real);
	int saved = errno;
	mg_inside--;
	errno = saved;
	return rc;
}

static int mg_execvp_hook(const char *file, char *const argv[]) {
	mg_sip_execvp_fn real_vp = mg_real_execvp;
	if (mg_inside || !getenv("MOGATE_SOCKET")) {
		if (!real_vp) { errno = ENOSYS; return -1; }
		return real_vp(file, argv);
	}
	mg_sip_execve_fn real_ve = mg_real_execve;
	if (!real_ve) {
		if (!real_vp) { errno = ENOSYS; return -1; }
		return real_vp(file, argv);
	}
	mg_inside++;
	int rc = mg_sip_execvp_detour(file, argv, mg_self_or_null(), getenv("MOGATE_SOCKET"), real_ve);
	int saved = errno;
	mg_inside--;
	errno = saved;
	return rc;
}

static int mg_posix_spawn_hook(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
	char *const argv[], char *const envp[]) {
	mg_sip_spawn_fn real = mg_real_posix_spawn;
	if (!real) return ENOSYS;
	if (mg_inside || !getenv("MOGATE_SOCKET")) return real(pid, path, fa, attr, argv, envp);
	// See mg_execve_hook: mg_inside makes the patch's own file/exec re-entries
	// pass through. posix_spawn reports errors via its return value, not errno.
	mg_inside++;
	int rc = mg_sip_posix_spawn_detour(pid, path, fa, attr, argv, envp,
		mg_self_or_null(), getenv("MOGATE_SOCKET"), real);
	mg_inside--;
	return rc;
}

static int mg_posix_spawnp_hook(pid_t *pid, const char *file,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
	char *const argv[], char *const envp[]) {
	mg_sip_spawn_fn real_p = mg_real_posix_spawnp;
	if (mg_inside || !getenv("MOGATE_SOCKET")) {
		if (!real_p) return ENOSYS;
		return real_p(pid, file, fa, attr, argv, envp);
	}
	mg_sip_spawn_fn real = mg_real_posix_spawn; // non-p: used after we PATH-resolve the target
	if (!real) {
		if (!real_p) return ENOSYS;
		return real_p(pid, file, fa, attr, argv, envp);
	}
	mg_inside++;
	int rc = mg_sip_posix_spawnp_detour(pid, file, fa, attr, argv, envp,
		mg_self_or_null(), getenv("MOGATE_SOCKET"), real);
	mg_inside--;
	return rc;
}
#endif // __APPLE__

#if defined(__APPLE__)
#define MG_INTERPOSE(replacement, replacee) \
	__attribute__((used)) static struct { const void *replacement; const void *replacee; } \
	mg_interpose_##replacee __attribute__((section("__DATA,__interpose"))) = \
	{ (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&replacee };

MG_INTERPOSE(mg_connect_hook, connect)
MG_INTERPOSE(mg_execve_hook, execve)
MG_INTERPOSE(mg_execvp_hook, execvp)
MG_INTERPOSE(mg_posix_spawn_hook, posix_spawn)
MG_INTERPOSE(mg_posix_spawnp_hook, posix_spawnp)
MG_INTERPOSE(mg_open_hook, open)
MG_INTERPOSE(mg_openat_hook, openat)
MG_INTERPOSE(mg_read_hook, read)
MG_INTERPOSE(mg_write_hook, write)
MG_INTERPOSE(mg_send_hook, send)
MG_INTERPOSE(mg_recv_hook, recv)
MG_INTERPOSE(mg_sendto_hook, sendto)
MG_INTERPOSE(mg_recvfrom_hook, recvfrom)
MG_INTERPOSE(mg_sendmsg_hook, sendmsg)
MG_INTERPOSE(mg_recvmsg_hook, recvmsg)
MG_INTERPOSE(mg_poll_hook, poll)
MG_INTERPOSE(mg_select_hook, select)
MG_INTERPOSE(mg_kevent_hook, kevent)
MG_INTERPOSE(mg_getsockopt_hook, getsockopt)
MG_INTERPOSE(mg_setsockopt_hook, setsockopt)
MG_INTERPOSE(mg_dup_hook, dup)
MG_INTERPOSE(mg_dup2_hook, dup2)
MG_INTERPOSE(mg_fcntl_hook, fcntl)
MG_INTERPOSE(mg_close_hook, close)
MG_INTERPOSE(mg_getaddrinfo_hook, getaddrinfo)
MG_INTERPOSE(mg_freeaddrinfo_hook, freeaddrinfo)
#else
__attribute__((visibility("default"))) int connect(int fd, const struct sockaddr *address, socklen_t size) { return mg_connect_hook(fd, address, size); }
__attribute__((visibility("default"))) int open(const char *path, int flags, ...) {
	mode_t mode = 0; if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
	return mg_open_hook(path, flags, mode);
}
__attribute__((visibility("default"))) int open64(const char *path, int flags, ...) {
	mode_t mode = 0; if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
	return mg_open_hook(path, flags, mode);
}
__attribute__((visibility("default"))) int __open_2(const char *path, int flags) { return mg_open_hook(path, flags, 0); }
__attribute__((visibility("default"))) int openat(int dir, const char *path, int flags, ...) {
	mode_t mode = 0; if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
	return mg_openat_hook(dir, path, flags, mode);
}
__attribute__((visibility("default"))) ssize_t read(int fd, void *buffer, size_t count) { return mg_read_hook(fd, buffer, count); }
__attribute__((visibility("default"))) ssize_t write(int fd, const void *buffer, size_t count) { return mg_write_hook(fd, buffer, count); }
__attribute__((visibility("default"))) ssize_t send(int fd, const void *buffer, size_t count, int flags) { return mg_send_hook(fd, buffer, count, flags); }
__attribute__((visibility("default"))) ssize_t recv(int fd, void *buffer, size_t count, int flags) { return mg_recv_hook(fd, buffer, count, flags); }
__attribute__((visibility("default"))) ssize_t sendto(int fd, const void *buffer, size_t count, int flags, const struct sockaddr *destination, socklen_t destination_size) { return mg_sendto_hook(fd, buffer, count, flags, destination, destination_size); }
__attribute__((visibility("default"))) ssize_t recvfrom(int fd, void *buffer, size_t count, int flags, struct sockaddr *source, socklen_t *source_size) { return mg_recvfrom_hook(fd, buffer, count, flags, source, source_size); }
__attribute__((visibility("default"))) ssize_t sendmsg(int fd, const struct msghdr *message, int flags) { return mg_sendmsg_hook(fd, message, flags); }
__attribute__((visibility("default"))) ssize_t recvmsg(int fd, struct msghdr *message, int flags) { return mg_recvmsg_hook(fd, message, flags); }
__attribute__((visibility("default"))) int poll(struct pollfd *descriptors, nfds_t count, int timeout) { return mg_poll_hook(descriptors, count, timeout); }
__attribute__((visibility("default"))) int select(int count, fd_set *read_set, fd_set *write_set, fd_set *error_set, struct timeval *timeout) { return mg_select_hook(count, read_set, write_set, error_set, timeout); }
__attribute__((visibility("default"))) int epoll_ctl(int epoll_fd, int operation, int fd, struct epoll_event *event) { return mg_epoll_ctl_hook(epoll_fd, operation, fd, event); }
__attribute__((visibility("default"))) int epoll_wait(int epoll_fd, struct epoll_event *events, int maximum, int timeout) { return mg_epoll_wait_hook(epoll_fd, events, maximum, timeout); }
__attribute__((visibility("default"))) int epoll_pwait(int epoll_fd, struct epoll_event *events, int maximum, int timeout, const sigset_t *mask) { return mg_epoll_pwait_hook(epoll_fd, events, maximum, timeout, mask); }
__attribute__((visibility("default"))) int getsockopt(int fd, int level, int option, void *value, socklen_t *size) { return mg_getsockopt_hook(fd, level, option, value, size); }
__attribute__((visibility("default"))) int setsockopt(int fd, int level, int option, const void *value, socklen_t size) { return mg_setsockopt_hook(fd, level, option, value, size); }
__attribute__((visibility("default"))) int dup(int fd) { return mg_dup_hook(fd); }
__attribute__((visibility("default"))) int dup2(int oldfd, int newfd) { return mg_dup2_hook(oldfd, newfd); }
__attribute__((visibility("default"))) int dup3(int oldfd, int newfd, int flags) { return mg_dup3_hook(oldfd, newfd, flags); }
__attribute__((visibility("default"))) int fcntl(int fd, int command, ...) {
	va_list args; va_start(args, command);
	int result;
	if (command == F_GETFD || command == F_GETFL) result = mg_fcntl_hook(fd, command);
	else { void *argument = va_arg(args, void *); result = mg_fcntl_hook(fd, command, argument); }
	va_end(args); return result;
}
__attribute__((visibility("default"))) int fcntl64(int fd, int command, ...) {
	va_list args; va_start(args, command);
	int result;
	if (command == F_GETFD || command == F_GETFL) result = mg_fcntl_hook(fd, command);
	else { void *argument = va_arg(args, void *); result = mg_fcntl_hook(fd, command, argument); }
	va_end(args); return result;
}
__attribute__((visibility("default"))) off_t lseek(int fd, off_t offset, int whence) { return mg_lseek_hook(fd, offset, whence); }
__attribute__((visibility("default"))) int fstat(int fd, struct stat *buffer) { return mg_fstat_hook(fd, buffer); }
__attribute__((visibility("default"))) int close(int fd) { return mg_close_hook(fd); }
__attribute__((visibility("default"))) int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) { return mg_getaddrinfo_hook(node, service, hints, result); }
__attribute__((visibility("default"))) void freeaddrinfo(struct addrinfo *result) { mg_freeaddrinfo_hook(result); }
#endif
*/
import "C"

func main() {}
