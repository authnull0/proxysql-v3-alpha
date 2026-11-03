#ifndef AUTHNULL_TLS_H
#define AUTHNULL_TLS_H

// How ProxySQL calls authn-service's do-authenticationV4 (DB-MFA-HARDENING S2).
//
// Every database login asks authn-service whether to let it in, and the request carries the
// user's connection token -- a bearer credential -- and, once AUTH-212 reaches ProxySQL, the
// proxy's own client credential. The answer decides the login. So the proxy must know it is
// talking to authn-service: the Postgres path turned certificate checks off
// (CURLOPT_SSL_VERIFYPEER/VERIFYHOST 0), and anyone on the network path could answer
// {"isValid": true} and collect every token sent to it.
//
// Settings, in [authnull] or the environment (the environment wins, as for api_url):
//
//   tls_verify          AUTHNULL_TLS_VERIFY           default true. false turns certificate
//                                                     checks off -- for a lab, never production;
//                                                     logged at every start.
//   ca_file             AUTHNULL_CA_FILE              a PEM bundle to trust, for an on-prem
//                                                     authn-service with a private CA. Empty: the
//                                                     system bundle curl was built with.
//   allow_insecure_http AUTHNULL_ALLOW_INSECURE_HTTP  default false. Plain http:// is accepted
//                                                     only to this machine (127.0.0.0/8, ::1,
//                                                     localhost) -- the on-prem monolith's
//                                                     127.0.0.1:2882 -- unless this is true.
//
// Redirects keep the scheme they started with: an https:// URL is never followed to http://,
// where the token would cross the network in the clear.
//
// Pure functions, no curl and no ProxySQL types, so test/authnull/authnull_tls_test.cpp can
// exercise them without a build.

#include <cctype>
#include <string>

struct AuthnullTlsSettings {
	bool verify = true;
	std::string ca_file;
	bool allow_insecure_http = false;
};

enum class AuthnullUrlScheme { Https, Http, Other };

namespace authnull_tls_detail {

inline std::string lower(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

inline std::string trimmed(const std::string& s) {
	size_t b = 0, e = s.size();
	while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) b++;
	while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;
	return s.substr(b, e - b);
}

// isIPv4Loopback: a dotted quad in 127.0.0.0/8.
inline bool isIPv4Loopback(const std::string& h) {
	int parts = 0, first = -1;
	size_t i = 0;
	for (;;) {
		size_t j = h.find('.', i);
		if (j == std::string::npos) j = h.size();
		std::string p = h.substr(i, j - i);
		if (p.empty() || p.size() > 3) return false;
		for (char c : p) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
		int v = std::stoi(p);
		if (v > 255) return false;
		if (parts++ == 0) first = v;
		if (j == h.size()) break;
		i = j + 1;
	}
	return parts == 4 && first == 127;
}

} // namespace authnull_tls_detail

// authnullParseBool reads true/false, yes/no, on/off, 1/0; anything else is fallback.
inline bool authnullParseBool(const std::string& s, bool fallback) {
	std::string v = authnull_tls_detail::lower(authnull_tls_detail::trimmed(s));
	if (v == "true" || v == "yes" || v == "on" || v == "1") return true;
	if (v == "false" || v == "no" || v == "off" || v == "0") return false;
	return fallback;
}

inline AuthnullUrlScheme authnullUrlScheme(const std::string& url) {
	std::string u = authnull_tls_detail::lower(authnull_tls_detail::trimmed(url));
	if (u.rfind("https://", 0) == 0) return AuthnullUrlScheme::Https;
	if (u.rfind("http://", 0) == 0) return AuthnullUrlScheme::Http;
	return AuthnullUrlScheme::Other;
}

// authnullUrlHost is the host of scheme://[userinfo@]host[:port][/...], lower-cased, IPv6
// brackets removed. Empty when there is none.
inline std::string authnullUrlHost(const std::string& url) {
	std::string u = authnull_tls_detail::trimmed(url);
	size_t s = u.find("://");
	if (s == std::string::npos) return "";
	std::string rest = u.substr(s + 3);
	size_t end = rest.find_first_of("/?#");
	std::string authority = rest.substr(0, end);
	size_t at = authority.rfind('@');
	if (at != std::string::npos) authority = authority.substr(at + 1);
	if (!authority.empty() && authority[0] == '[') {
		size_t close = authority.find(']');
		if (close == std::string::npos) return "";
		return authnull_tls_detail::lower(authority.substr(1, close - 1));
	}
	size_t colon = authority.find(':');
	return authnull_tls_detail::lower(authority.substr(0, colon));
}

// authnullIsLoopbackHost: this machine, by name or address.
inline bool authnullIsLoopbackHost(const std::string& host) {
	return host == "localhost" || host == "::1" || authnull_tls_detail::isIPv4Loopback(host);
}

// authnullApiUrlProblem says why ProxySQL must not call url, or returns "" when it may.
inline std::string authnullApiUrlProblem(const std::string& url, const AuthnullTlsSettings& s) {
	if (authnull_tls_detail::trimmed(url).empty()) return "api_url is not set";
	switch (authnullUrlScheme(url)) {
	case AuthnullUrlScheme::Https:
		if (authnullUrlHost(url).empty()) return "api_url has no host";
		return "";
	case AuthnullUrlScheme::Http:
		if (authnullUrlHost(url).empty()) return "api_url has no host";
		if (authnullIsLoopbackHost(authnullUrlHost(url)) || s.allow_insecure_http) return "";
		return "api_url is plain http:// to another machine, so connection tokens would cross the "
		       "network unencrypted and anyone on the path could answer for authn-service; use "
		       "https://, or set allow_insecure_http = true in [authnull] to accept the risk";
	case AuthnullUrlScheme::Other:
		break;
	}
	return "api_url must start with https:// (or http:// to this machine)";
}

// AuthnullCurlTls is what to set on the curl handle for url.
struct AuthnullCurlTls {
	long verify_peer;       // CURLOPT_SSL_VERIFYPEER
	long verify_host;       // CURLOPT_SSL_VERIFYHOST
	std::string ca_file;    // CURLOPT_CAINFO, when not empty
	const char* protocols;  // CURLOPT_PROTOCOLS_STR and CURLOPT_REDIR_PROTOCOLS_STR
};

inline AuthnullCurlTls authnullCurlTls(const std::string& url, const AuthnullTlsSettings& s) {
	AuthnullCurlTls t;
	t.verify_peer = s.verify ? 1L : 0L;
	t.verify_host = s.verify ? 2L : 0L;
	t.ca_file = authnull_tls_detail::trimmed(s.ca_file);
	// Pinned to the URL's own scheme, for the request and any redirect: https stays https.
	t.protocols = authnullUrlScheme(url) == AuthnullUrlScheme::Http ? "http" : "https";
	return t;
}

#endif // AUTHNULL_TLS_H
