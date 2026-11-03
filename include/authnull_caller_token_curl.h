#ifndef AUTHNULL_CALLER_TOKEN_CURL_H
#define AUTHNULL_CALLER_TOKEN_CURL_H

// The HTTP half of the proxy's caller credential (see authnull_caller_token.h): the token request,
// and the header added to every do-authenticationV4 call. Shared by the Postgres
// (PgSQL_Protocol.cpp) and MySQL (MySQL_Session.cpp) paths: one credential, one cache.

// Include after <syslog.h>: its LOG_* macros break re2's logging.h when they come first, so this
// header leaves including it to the file.
#include <curl/curl.h>

#include <ctime>
#include <mutex>
#include <string>

#include "authnull_caller_token.h"
#include "authnull_tls.h"

struct AuthnullCallerConfig {
	std::string client_id;
	std::string client_secret;
	std::string token_url;
	AuthnullTlsSettings tls;
	std::string problem; // why no credential will be sent although one is configured
};

namespace authnull_caller_detail {

inline std::mutex& configMutex() {
	static std::mutex mu;
	return mu;
}

inline AuthnullCallerConfig& config() {
	static AuthnullCallerConfig c;
	return c;
}

inline size_t write(void* contents, size_t size, size_t nmemb, void* out) {
	static_cast<std::string*>(out)->append(static_cast<char*>(contents), size * nmemb);
	return size * nmemb;
}

inline bool fetch(std::string& token, long& expires_in, std::string& err) {
	AuthnullCallerConfig cfg;
	{
		std::lock_guard<std::mutex> lock(configMutex());
		cfg = config();
	}
	if (!cfg.problem.empty()) {
		err = cfg.problem;
		return false;
	}
	CURL* curl = curl_easy_init();
	if (!curl) {
		err = "curl initialisation failed";
		return false;
	}
	std::string body = nlohmann::json{{"clientId", cfg.client_id}, {"clientSecret", cfg.client_secret}}.dump();
	std::string response;
	struct curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
	AuthnullCurlTls tls = authnullCurlTls(cfg.token_url, cfg.tls);
	curl_easy_setopt(curl, CURLOPT_URL, cfg.token_url.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	// The secret is in the body: no redirects at all, so it goes only where token_url says.
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, tls.verify_peer);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, tls.verify_host);
	if (!tls.ca_file.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, tls.ca_file.c_str());
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, tls.protocols);
	CURLcode res = curl_easy_perform(curl);
	long code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		err = std::string("token request failed: ") + curl_easy_strerror(res);
		return false;
	}
	if (code != 200) {
		err = "token endpoint answered " + std::to_string(code) +
		      (code == 401 ? " (client_id/client_secret refused: revoked, or from another install?)" : "");
		return false;
	}
	if (!authnullParseTokenResponse(response, token, expires_in)) {
		err = "token endpoint answered 200 without a database-proxy token";
		return false;
	}
	return true;
}

inline AuthnullCallerToken& cache() {
	static AuthnullCallerToken t(fetch, [] { return static_cast<long>(std::time(nullptr)); });
	return t;
}

} // namespace authnull_caller_detail

// authnullConfigureCaller records the caller credential settings and reports, once, what will
// happen. Both login paths call it with the same values when they load [authnull].
inline void authnullConfigureCaller(const std::string& client_id, const std::string& client_secret,
                                    const std::string& token_url, const AuthnullTlsSettings& tls) {
	AuthnullCallerConfig c;
	c.client_id = authnull_tls_detail::trimmed(client_id);
	c.client_secret = authnull_tls_detail::trimmed(client_secret);
	c.token_url = authnull_tls_detail::trimmed(token_url);
	c.tls = tls;
	bool any = !c.client_id.empty() || !c.client_secret.empty() || !c.token_url.empty();
	if (any) {
		if (c.client_id.empty() || c.client_secret.empty() || c.token_url.empty()) {
			c.problem = "client_id, client_secret and token_url must all be set";
		} else if (c.client_id.rfind("dpc-", 0) != 0) {
			c.problem = "client_id is not a database-proxy client id (dpc-...)";
		} else {
			std::string p = authnullApiUrlProblem(c.token_url, tls);
			if (p.rfind("api_url", 0) == 0) p = "token_url" + p.substr(7); // the same rules, its own name
			if (!p.empty()) c.problem = p + " -- the client secret is not sent";
		}
	}
	bool changed;
	{
		static bool reported = false;
		std::lock_guard<std::mutex> lock(authnull_caller_detail::configMutex());
		AuthnullCallerConfig& cur = authnull_caller_detail::config();
		changed = !reported || cur.client_id != c.client_id || cur.client_secret != c.client_secret ||
		          cur.token_url != c.token_url || cur.problem != c.problem;
		cur = c;
		reported = true;
	}
	if (!changed) return;
	if (!any) {
		syslog(LOG_WARNING, "[authnull] no client_id/client_secret/token_url: authn-service is called without a caller credential, "
		                    "which it refuses once AUTHN_REQUIRE_CALLER_AUTH is on. Download a fresh db.env for this proxy.");
	} else if (!c.problem.empty()) {
		syslog(LOG_ERR, "[authnull] caller credential not used: %s", c.problem.c_str());
	} else {
		syslog(LOG_INFO, "[authnull] caller credential %s, tokens from %s", c.client_id.c_str(), c.token_url.c_str());
	}
}

// authnullAddCallerAuth adds "Authorization: Bearer <token>" to headers when the proxy has a
// credential, and returns the token sent ("" when none). Never fails a login on its own:
// without a token authn-service decides, by its AUTHN_REQUIRE_CALLER_AUTH.
inline std::string authnullAddCallerAuth(struct curl_slist*& headers) {
	{
		std::lock_guard<std::mutex> lock(authnull_caller_detail::configMutex());
		const AuthnullCallerConfig& c = authnull_caller_detail::config();
		if (c.client_id.empty() || !c.problem.empty()) return "";
	}
	std::string err;
	std::string token = authnull_caller_detail::cache().get(err);
	if (!err.empty()) {
		syslog(LOG_ERR, "[authnull] caller token: %s%s", err.c_str(), token.empty() ? "; calling authn-service without one" : "");
	}
	if (token.empty()) return "";
	headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
	return token;
}

// authnullCallerTokenRefused: authn-service answered 401 or 403 to a call that carried token, so
// the next login fetches a new one.
inline void authnullCallerTokenRefused(const std::string& token, long http_code) {
	if (token.empty() || (http_code != 401 && http_code != 403)) return;
	syslog(LOG_WARNING, "[authnull] authn-service answered %ld to this proxy's caller token; fetching a new one on the next login", http_code);
	authnull_caller_detail::cache().invalidate(token);
}

#endif // AUTHNULL_CALLER_TOKEN_CURL_H
