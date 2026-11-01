// Standalone test for include/authnull_net.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_net_test.cpp -o /tmp/authnull_net_test && /tmp/authnull_net_test
//
// Exits non-zero on the first failure.
#include "authnull_net.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

static int failures = 0;

static void expect(const std::string& got, const std::string& want, const char* what) {
	if (got != want) {
		std::fprintf(stderr, "FAIL %s: got '%s', want '%s'\n", what, got.c_str(), want.c_str());
		failures++;
	}
}

static sockaddr_storage v4(const char* addr) {
	sockaddr_storage ss{};
	auto* in = reinterpret_cast<sockaddr_in*>(&ss);
	in->sin_family = AF_INET;
	inet_pton(AF_INET, addr, &in->sin_addr);
	return ss;
}

static sockaddr_storage v6(const char* addr) {
	sockaddr_storage ss{};
	auto* in6 = reinterpret_cast<sockaddr_in6*>(&ss);
	in6->sin6_family = AF_INET6;
	inet_pton(AF_INET6, addr, &in6->sin6_addr);
	return ss;
}

int main() {
	// Addresses as the policy engine compares them.
	expect(authnullSockaddrIP(v4("10.1.2.3")), "10.1.2.3", "IPv4");
	expect(authnullSockaddrIP(v6("2001:db8::1")), "2001:db8::1", "IPv6");
	// A dual-stack listener sees IPv4 clients as ::ffff:a.b.c.d. That is the IPv4 address, and a
	// network condition written as 10.0.0.0/8 must match it.
	expect(authnullSockaddrIP(v6("::ffff:10.1.2.3")), "10.1.2.3", "IPv4-mapped IPv6");
	sockaddr_storage unix_ss{};
	unix_ss.ss_family = AF_UNIX;
	expect(authnullSockaddrIP(unix_ss), "", "a Unix socket has no IP");

	// The proxy's address: configured wins; otherwise the local end of the client's connection.
	expect(authnullProxyAddress(" 192.0.2.10 ", -1), "192.0.2.10", "configured, trimmed");
	expect(authnullProxyAddress("", -1), "", "nothing configured, no socket");

	// A real connected socket: its local address is what getsockname reports.
	int srv = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	listen(srv, 1);
	socklen_t len = sizeof(addr);
	getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &len);
	int cli = socket(AF_INET, SOCK_STREAM, 0);
	connect(cli, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	int acc = accept(srv, nullptr, nullptr);
	expect(authnullLocalAddress(acc), "127.0.0.1", "local address of an accepted connection");
	expect(authnullPeerAddress(acc), "127.0.0.1", "peer address of an accepted connection");
	expect(authnullProxyAddress("", acc), "127.0.0.1", "nothing configured: the connection's local address");
	close(acc);
	close(cli);
	close(srv);

	expect(authnullLocalAddress(-1), "", "no socket");
	expect(authnullPeerAddress(-1), "", "no socket");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("ok\n");
	return 0;
}
