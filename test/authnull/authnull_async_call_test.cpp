// Standalone test for authnull_async_call.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_async_call_test.cpp -pthread -o /tmp/authnull_async_call_test && /tmp/authnull_async_call_test
//
// The push-MFA call blocks until the person answers (up to 90 s). Made on a ProxySQL worker thread,
// it froze every other session on that thread for as long (measured on the lab, 9 Nov: 20 s holds,
// every session on the thread stalled). AuthnullAsyncCall runs it elsewhere; the worker only polls.
#include "authnull_async_call.h"

#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

using namespace std::chrono;
using Call = AuthnullAsyncCall<std::string>;

static bool waitDone(const std::shared_ptr<Call>& c, milliseconds limit) {
	auto end = steady_clock::now() + limit;
	while (!c->done()) {
		if (steady_clock::now() > end) return false;
		std::this_thread::sleep_for(milliseconds(5));
	}
	return true;
}

static bool waitIdle(milliseconds limit) {
	auto end = steady_clock::now() + limit;
	while (Call::in_flight() != 0) {
		if (steady_clock::now() > end) return false;
		std::this_thread::sleep_for(milliseconds(5));
	}
	return true;
}

int main() {
	// Starting does not wait for the call: the worker thread is free at once.
	{
		auto t = steady_clock::now();
		auto c = Call::start([] { std::this_thread::sleep_for(milliseconds(300)); return std::string("approved"); });
		CHECK(c != nullptr, "start refused");
		CHECK(steady_clock::now() - t < milliseconds(50), "start waited for the call");
		CHECK(!c->done(), "done before the call returned");
		CHECK(Call::in_flight() == 1, "in_flight while running");
		CHECK(waitDone(c, milliseconds(2000)), "never done");
		CHECK(c->take() == "approved", "result");
		CHECK(waitIdle(milliseconds(500)), "in_flight after the call");
	}

	// The session can go (client hung up) while the call runs: nothing crashes, the slot is freed.
	{
		auto c = Call::start([] { std::this_thread::sleep_for(milliseconds(100)); return std::string("late"); });
		CHECK(c != nullptr, "start refused");
		c.reset();
		CHECK(waitIdle(milliseconds(1000)), "an abandoned call kept its slot");
	}

	// A call that throws is done, with an empty result: a refusal, never an approval.
	{
		auto c = Call::start([]() -> std::string { throw std::runtime_error("boom"); });
		CHECK(c != nullptr, "start refused");
		CHECK(waitDone(c, milliseconds(1000)), "a throwing call never finished");
		CHECK(c->take().empty(), "a throwing call returned something");
	}

	// A cap on calls in flight: past it, start refuses (the login is denied) instead of making
	// threads without bound; a finished call frees its slot.
	{
		CHECK(waitIdle(milliseconds(1000)), "not idle before the cap test");
		Call::set_limit(2);
		auto a = Call::start([] { std::this_thread::sleep_for(milliseconds(200)); return std::string("a"); });
		auto b = Call::start([] { std::this_thread::sleep_for(milliseconds(200)); return std::string("b"); });
		auto c = Call::start([] { return std::string("c"); });
		CHECK(a && b, "under the cap refused");
		CHECK(c == nullptr, "over the cap accepted");
		CHECK(waitDone(a, milliseconds(1000)) && waitDone(b, milliseconds(1000)), "capped calls never finished");
		CHECK(waitIdle(milliseconds(500)), "slots not freed");
		auto d = Call::start([] { return std::string("d"); });
		CHECK(d != nullptr && waitDone(d, milliseconds(1000)) && d->take() == "d", "a freed slot was not reusable");
		Call::set_limit(0);  // back to the default
		CHECK(Call::limit() > 2, "the default cap");
	}

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
