// authnull_net.h -- addresses AuthNull's MFA request carries, worked out locally.
//
// Two addresses go to authn-service with every database login:
//
//   userIp         the CLIENT's address -- who is connecting. AuthNull's policy engine checks
//                  network conditions against it, so it must be the client and nothing else.
//   database_host  the PROXY's address -- shown as the gateway in the MFA prompt.
//
// The proxy's address used to come from https://api.ipify.org, fetched on every login (and on
// every MySQL query, for a log line). That put an outbound internet call on the login path:
// latency on each one, a hang or an empty value on an air-gapped install, and a third party told
// when customers' databases are in use. It is now the address configured as
// AUTHNULL_PROXY_ADDRESS / [authnull] proxy_address, or, when none is, the local end of the
// client's own connection -- the proxy's address as that client reached it.
//
// Self-contained so it can be tested without a ProxySQL build: see
// test/authnull/authnull_net_test.cpp.
#ifndef AUTHNULL_NET_H
#define AUTHNULL_NET_H

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// authnullSockaddrIP is the printable IP of an IPv4 or IPv6 socket address, or "" for anything
// else. An IPv4-mapped IPv6 address (::ffff:a.b.c.d, what a dual-stack listener reports for an
// IPv4 client) is returned as plain IPv4, so a condition written as 10.0.0.0/8 matches it.
inline std::string authnullSockaddrIP(const sockaddr_storage& ss) {
	char buf[INET6_ADDRSTRLEN] = {0};
	if (ss.ss_family == AF_INET) {
		const auto* in = reinterpret_cast<const sockaddr_in*>(&ss);
		if (inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)) != nullptr) {
			return buf;
		}
		return "";
	}
	if (ss.ss_family == AF_INET6) {
		const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&ss);
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			if (inet_ntop(AF_INET, &in6->sin6_addr.s6_addr[12], buf, sizeof(buf)) != nullptr) {
				return buf;
			}
			return "";
		}
		if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf)) != nullptr) {
			return buf;
		}
	}
	return "";
}

// authnullLocalAddress is the local address of a connected socket: on an accepted client
// connection, the proxy's own address as the client reached it. "" when it cannot be read.
inline std::string authnullLocalAddress(int fd) {
	if (fd < 0) {
		return "";
	}
	sockaddr_storage ss{};
	socklen_t len = sizeof(ss);
	if (getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
		return "";
	}
	return authnullSockaddrIP(ss);
}

// authnullPeerAddress is the remote address of a connected socket: on an accepted client
// connection, the client. "" when it cannot be read.
inline std::string authnullPeerAddress(int fd) {
	if (fd < 0) {
		return "";
	}
	sockaddr_storage ss{};
	socklen_t len = sizeof(ss);
	if (getpeername(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
		return "";
	}
	return authnullSockaddrIP(ss);
}

// authnullProxyAddress is the address to send as database_host: the configured one when set,
// otherwise the local end of the client's connection. Never a network call.
inline std::string authnullProxyAddress(const std::string& configured, int client_fd) {
	const char* ws = " \t\r\n";
	size_t b = configured.find_first_not_of(ws);
	if (b != std::string::npos) {
		size_t e = configured.find_last_not_of(ws);
		return configured.substr(b, e - b + 1);
	}
	return authnullLocalAddress(client_fd);
}

#endif // AUTHNULL_NET_H
