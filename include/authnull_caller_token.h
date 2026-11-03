#ifndef AUTHNULL_CALLER_TOKEN_H
#define AUTHNULL_CALLER_TOKEN_H

// The proxy's own credential to authn-service (DB-MFA-HARDENING S3, AUTH-212).
//
// authn-service decides every database login, and until now anyone who could reach it could ask:
// name an org and a user, and that person's phone buzzes. Each proxy now has a client id and
// secret (issued with its db.env, authnull-service internal/database/proxyauth), trades them at
// token_url for a bearer token that lives 15 minutes, and sends it on every do-authenticationV4
// call. authn-service lets that token ask only for database logins of its own org and tenant.
//
// Settings, in [authnull] or the environment (the environment wins):
//
//   client_id      AUTHNULL_CLIENT_ID      dpc-<org>-...
//   client_secret  AUTHNULL_CLIENT_SECRET  dps_...
//   token_url      AUTHNULL_TOKEN_URL      https://<api host>/api/v1/database/proxy/token
//
// All three unset: no credential is sent, as before, and authn-service accepts that only while
// AUTHN_REQUIRE_CALLER_AUTH is off. token_url is held to the same rules as api_url
// (authnull_tls.h): the secret is never sent over plain http to another machine.
//
// This header is the cache and the response parsing, with no curl, so
// test/authnull/authnull_caller_token_test.cpp can exercise it without a build. The HTTP fetch
// is authnull_caller_token_curl.h.

#include <functional>
#include <mutex>
#include <string>

#include "../deps/json/json.hpp"

// authnullParseTokenResponse reads {"accessToken": "...", "expiresIn": n} from the token
// endpoint. False for anything else, including a token that is not a db-proxy token.
inline bool authnullParseTokenResponse(const std::string& body, std::string& token, long& expires_in) {
	try {
		auto j = nlohmann::json::parse(body);
		if (!j.is_object() || !j.contains("accessToken") || !j["accessToken"].is_string()) return false;
		std::string t = j["accessToken"].get<std::string>();
		if (t.rfind("dpt.", 0) != 0) return false;
		long e = 0;
		if (j.contains("expiresIn") && j["expiresIn"].is_number_integer()) e = j["expiresIn"].get<long>();
		if (e <= 0) return false;
		token = t;
		expires_in = e;
		return true;
	} catch (...) {
		return false;
	}
}

// AuthnullCallerToken caches the proxy's token and fetches a new one when it is close to expiry.
// One fetch at a time: logins arriving while one is in flight wait for it rather than each
// asking. A failed fetch is not retried for retry_after seconds, so an outage of the token
// endpoint does not add a request to every login.
class AuthnullCallerToken {
public:
	// Fetch asks the token endpoint. On success it sets token and expires_in (seconds).
	using Fetch = std::function<bool(std::string& token, long& expires_in, std::string& err)>;
	using Clock = std::function<long()>; // seconds

	AuthnullCallerToken(Fetch fetch, Clock now, long refresh_before = 60, long retry_after = 10)
		: fetch_(std::move(fetch)), now_(std::move(now)), refresh_before_(refresh_before), retry_after_(retry_after) {}

	// get returns a token to send, or "" when there is none. err says why there is none, or why a
	// refresh failed while an older, still-valid token is returned.
	std::string get(std::string& err) {
		std::lock_guard<std::mutex> lock(mu_);
		err.clear();
		long now = now_();
		if (!token_.empty() && now < expires_at_ - refresh_before_) return token_;
		if (now < next_attempt_) {
			if (!token_.empty() && now < expires_at_) return token_;
			err = last_err_;
			return "";
		}
		std::string t, e;
		long in = 0;
		if (fetch_(t, in, e) && !t.empty() && in > 0) {
			token_ = t;
			expires_at_ = now + in;
			last_err_.clear();
			return token_;
		}
		last_err_ = e.empty() ? "token request failed" : e;
		next_attempt_ = now + retry_after_;
		err = last_err_;
		if (!token_.empty() && now < expires_at_) return token_;
		token_.clear();
		return "";
	}

	// invalidate drops token if it is the cached one: authn-service refused it (revoked, or the
	// credential's tenant no longer matches). The next login fetches a new one.
	void invalidate(const std::string& token) {
		std::lock_guard<std::mutex> lock(mu_);
		if (!token.empty() && token == token_) {
			token_.clear();
			expires_at_ = 0;
			next_attempt_ = 0;
		}
	}

private:
	Fetch fetch_;
	Clock now_;
	long refresh_before_;
	long retry_after_;
	std::mutex mu_;
	std::string token_;
	long expires_at_ = 0;
	long next_attempt_ = 0;
	std::string last_err_;
};

#endif // AUTHNULL_CALLER_TOKEN_H
