#ifndef AUTHNULL_ASYNC_CALL_H
#define AUTHNULL_ASYNC_CALL_H

// A blocking call made off the worker thread.
//
// The push-MFA login call (do-authenticationV4) blocks until the person answers their phone: up to
// the push's 60 s TTL, 90 s with headroom. ProxySQL runs many client sessions on each worker thread,
// so making that call in the handshake froze every session on the thread -- running queries and new
// logins alike -- for as long as the push went unanswered (measured on the lab, 9 Nov 2026: with 4
// threads, a quarter of the sessions stalled for the whole hold; four unanswered pushes would stall
// them all).
//
// AuthnullAsyncCall runs the call on a thread of its own. The session starts it, returns to the
// worker loop, and polls done() until the answer is in. The call holds its own reference, so a
// session that goes away (the client hung up) leaves it to finish and be freed.
//
// Calls in flight are capped (limit(), default 512): past the cap, start() refuses and the login is
// denied, rather than making threads without bound. test/authnull/authnull_async_call_test.cpp.

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

template <class R>
class AuthnullAsyncCall {
public:
	static constexpr int kDefaultLimit = 512;

	// start runs fn on its own thread. nullptr when the cap is reached or no thread can be made.
	static std::shared_ptr<AuthnullAsyncCall> start(std::function<R()> fn) {
		int n = inFlight().fetch_add(1);
		if (n >= limit()) {
			inFlight().fetch_sub(1);
			return nullptr;
		}
		std::shared_ptr<AuthnullAsyncCall> call(new AuthnullAsyncCall());
		try {
			std::thread([call, fn]() {
				R r{};
				try {
					r = fn();
				} catch (...) {
					r = R{}; // a call that fails is a refusal
				}
				{
					std::lock_guard<std::mutex> g(call->mu_);
					call->result_ = std::move(r);
				}
				call->done_.store(true);
				inFlight().fetch_sub(1);
			}).detach();
		} catch (...) {
			inFlight().fetch_sub(1);
			return nullptr;
		}
		return call;
	}

	bool done() const { return done_.load(); }

	// take is the result; call it once done() is true.
	R take() {
		std::lock_guard<std::mutex> g(mu_);
		return std::move(result_);
	}

	static int in_flight() { return inFlight().load(); }
	static int limit() { int l = limitRef().load(); return l > 0 ? l : kDefaultLimit; }
	// set_limit changes the cap; 0 restores the default.
	static void set_limit(int n) { limitRef().store(n); }

private:
	AuthnullAsyncCall() = default;
	static std::atomic<int>& inFlight() { static std::atomic<int> n{0}; return n; }
	static std::atomic<int>& limitRef() { static std::atomic<int> n{0}; return n; }

	std::atomic<bool> done_{false};
	std::mutex mu_;
	R result_{};
};

#endif // AUTHNULL_ASYNC_CALL_H
