// Standalone test for include/authnull_curl_cancel.h with authnull_mfa_call.h. Needs libcurl; run
// from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_curl_cancel_test.cpp -lcurl -pthread -o /tmp/authnull_curl_cancel_test && /tmp/authnull_curl_cancel_test
//
// The push-MFA login call blocks up to 90 s while the person decides. If the client hangs up in the
// meantime, the session cancels the call: curl must drop the request within about a second, so that
// authn-service sees its client go and does not log an approval given afterwards as an access
// (lab, 24 Nov 2026). A stand-in authn-service here accepts the request and never answers, as
// do-authenticationV4 does while the push is pending.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "authnull_curl_cancel.h"
#include "authnull_mfa_call.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

using namespace std::chrono;

// listenLocal listens on 127.0.0.1 on a port of the kernel's choosing.
static int listenLocal(int& port) {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	if (s < 0 || bind(s, (sockaddr*)&a, sizeof a) != 0 || listen(s, 4) != 0) return -1;
	socklen_t l = sizeof a;
	getsockname(s, (sockaddr*)&a, &l);
	port = ntohs(a.sin_port);
	return s;
}

// closedWithin: whether the peer of fd closes the connection within limit (read returns 0 or fails).
static bool closedWithin(int fd, milliseconds limit) {
	auto end = steady_clock::now() + limit;
	char buf[4096];
	while (steady_clock::now() < end) {
		pollfd p{fd, POLLIN, 0};
		if (poll(&p, 1, 50) > 0) {
			ssize_t n = read(fd, buf, sizeof buf);
			if (n <= 0) return true;
		}
	}
	return false;
}

static size_t keep(void* data, size_t size, size_t n, void* out) {
	static_cast<std::string*>(out)->append(static_cast<char*>(data), size * n);
	return size * n;
}

static AuthnullMfaAnswer post(const std::string& url, const std::atomic<bool>& cancelled) {
	AuthnullMfaAnswer a;
	CURL* c = curl_easy_init();
	if (!c) return a;
	curl_easy_setopt(c, CURLOPT_URL, url.c_str());
	curl_easy_setopt(c, CURLOPT_POSTFIELDS, "{}");
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, keep);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &a.body);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
	curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
	authnullCurlCancelOn(c, &cancelled);
	a.curl_code = (int)curl_easy_perform(c);
	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &a.http_code);
	curl_easy_cleanup(c);
	return a;
}

int main() {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	int port = 0;
	int ls = listenLocal(port);
	CHECK(ls >= 0, "listen");
	if (ls < 0) return 1;
	std::string url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1/auth/do-authenticationV4";

	// A push nobody has answered yet: the call waits. The client hangs up and the session cancels the
	// call: curl gives up, and the stand-in authn-service sees its connection close.
	{
		auto call = AuthnullMfaCall::start_cancellable([url](const std::atomic<bool>& cancelled) { return post(url, cancelled); });
		CHECK(call != nullptr, "start refused");
		int conn = accept(ls, nullptr, nullptr);
		CHECK(conn >= 0, "accept");
		std::this_thread::sleep_for(milliseconds(1500)); // the push is pending
		CHECK(!call->done(), "the call ended before anyone answered");
		auto t = steady_clock::now();
		call->cancel();
		call.reset(); // the session is gone
		CHECK(closedWithin(conn, milliseconds(3000)), "authn-service never saw the proxy go");
		auto took = duration_cast<milliseconds>(steady_clock::now() - t).count();
		CHECK(took < 3000, "the cancel took too long to reach the connection");
		std::printf("connection closed %lld ms after cancel\n", (long long)took);
		close(conn);
	}

	// The same call, not cancelled, still gets its answer: the check changes nothing for a client
	// that waits.
	{
		auto call = AuthnullMfaCall::start_cancellable([url](const std::atomic<bool>& cancelled) { return post(url, cancelled); });
		CHECK(call != nullptr, "start refused");
		int conn = accept(ls, nullptr, nullptr);
		CHECK(conn >= 0, "accept");
		std::this_thread::sleep_for(milliseconds(1500)); // the person decides
		const char* ok = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"isValid\":true}";
		CHECK(write(conn, ok, strlen(ok)) > 0, "answer");
		auto end = steady_clock::now() + milliseconds(3000);
		while (!call->done() && steady_clock::now() < end) std::this_thread::sleep_for(milliseconds(10));
		CHECK(call->done(), "never done");
		AuthnullMfaAnswer a = call->take();
		CHECK(a.curl_code == CURLE_OK, "an uncancelled call failed");
		CHECK(a.http_code == 200 && a.body == "{\"isValid\":true}", "an uncancelled call lost its answer");
		close(conn);
	}

	// The answer of a cancelled call is a curl failure (CURLE_ABORTED_BY_CALLBACK), which the login
	// paths treat as a refusal, never as an approval.
	{
		auto call = AuthnullMfaCall::start_cancellable([url](const std::atomic<bool>& cancelled) { return post(url, cancelled); });
		int conn = accept(ls, nullptr, nullptr);
		call->cancel();
		auto end = steady_clock::now() + milliseconds(3000);
		while (!call->done() && steady_clock::now() < end) std::this_thread::sleep_for(milliseconds(10));
		CHECK(call->done(), "a cancelled call never finished");
		CHECK(call->take().curl_code == CURLE_ABORTED_BY_CALLBACK, "a cancelled call did not abort");
		close(conn);
	}

	close(ls);
	curl_global_cleanup();
	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
