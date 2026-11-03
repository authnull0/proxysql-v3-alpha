// Standalone test for include/authnull_tls.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_tls_test.cpp -o /tmp/authnull_tls_test && /tmp/authnull_tls_test
#include "authnull_tls.h"

#include <cstdio>
#include <cstring>
#include <string>

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}

static bool allowed(const std::string& url, const AuthnullTlsSettings& s = AuthnullTlsSettings()) {
	return authnullApiUrlProblem(url, s).empty();
}

int main() {
	const AuthnullTlsSettings defaults;

	// Certificate checks are on unless turned off: the Postgres path had them off, so anyone on the
	// network path could answer {"isValid": true}.
	{
		AuthnullCurlTls t = authnullCurlTls("https://onprem.example.com/authnull0/api/v1/authn/v3/do-authenticationV4", defaults);
		expect(t.verify_peer == 1 && t.verify_host == 2, "verification on by default");
		expect(t.ca_file.empty(), "no CA file unless configured");
		expect(std::strcmp(t.protocols, "https") == 0, "https URL: https only, redirects included");
	}
	{
		AuthnullTlsSettings s;
		s.verify = false;
		s.ca_file = "  /etc/authnull/ca.pem ";
		AuthnullCurlTls t = authnullCurlTls("https://h/x", s);
		expect(t.verify_peer == 0 && t.verify_host == 0, "tls_verify=false turns both checks off");
		expect(t.ca_file == "/etc/authnull/ca.pem", "ca_file passed through, trimmed");
	}
	// A redirect can't take an https request to http, where the token would travel in the clear.
	expect(std::strcmp(authnullCurlTls("HTTPS://h/x", defaults).protocols, "https") == 0, "scheme is case-insensitive");
	expect(std::strcmp(authnullCurlTls("http://127.0.0.1:2882/x", defaults).protocols, "http") == 0, "local http stays http");

	// Which URLs may be called.
	expect(allowed("https://onprem.dev.authnull.com/authnull0/api/v1/authn/v3/do-authenticationV4"), "https to anywhere");
	expect(allowed("http://127.0.0.1:2882/authnull0/api/v1/authn/v3/do-authenticationV4"), "the on-prem monolith's local port");
	expect(allowed("http://127.1.2.3:2882/x"), "all of 127.0.0.0/8");
	expect(allowed("http://localhost:2882/x"), "localhost");
	expect(allowed("http://LOCALHOST:2882/x"), "localhost, any case");
	expect(allowed("http://[::1]:2882/x"), "IPv6 loopback");
	expect(!allowed("http://192.168.122.15:2882/x"), "plain http to another machine is refused");
	expect(!allowed("http://onprem.dev.authnull.com/x"), "plain http to a hostname is refused");
	expect(!allowed("http://127.0.0.1.evil.example/x"), "a hostname that starts like loopback is not loopback");
	expect(!allowed("http://localhost.evil.example/x"), "nor one that starts with localhost");
	expect(!allowed("http://user@evil.example/x") && allowed("http://evil.example@127.0.0.1/x"), "the host is after the userinfo");
	expect(!allowed("http://1270.0.0.1/x") && !allowed("http://127.0.0/x") && !allowed("http://127.0.0.256/x"), "malformed addresses are not loopback");
	{
		AuthnullTlsSettings s;
		s.allow_insecure_http = true;
		expect(allowed("http://192.168.122.15:2882/x", s), "allow_insecure_http accepts remote http");
	}
	expect(!allowed(""), "empty api_url");
	expect(!allowed("ftp://h/x") && !allowed("h/x") && !allowed("file:///etc/passwd"), "other schemes");
	expect(!allowed("https:///x") && !allowed("http://"), "no host");
	expect(authnullApiUrlProblem("http://10.0.0.1/x", defaults).find("allow_insecure_http") != std::string::npos,
		"the refusal names the setting that overrides it");

	expect(authnullUrlHost("https://u:p@Host.Example:8443/a?b") == "host.example", "host parsing");
	expect(authnullUrlHost("http://[::1]:2882/x") == "::1", "IPv6 host parsing");

	// Booleans as operators write them.
	expect(authnullParseBool("false", true) == false && authnullParseBool(" No ", true) == false && authnullParseBool("0", true) == false, "false values");
	expect(authnullParseBool("TRUE", false) && authnullParseBool("on", false) && authnullParseBool("1", false), "true values");
	expect(authnullParseBool("", true) && !authnullParseBool("maybe", false), "anything else is the default");

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
