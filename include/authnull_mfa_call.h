#ifndef AUTHNULL_MFA_CALL_H
#define AUTHNULL_MFA_CALL_H

// The push-MFA login call, made off the worker thread (authnull_async_call.h).
//
// PgSQL_Protocol::process_handshake_response_packet starts it and answers PENDING_MFA; the session
// keeps the client's password packet (PgSQL_Session::authnull_mfa_pkt), the worker thread looks at
// the session again every 100 ms (PgSQL_Thread::process_all_sessions), and once the call is done
// the packet goes back to the session's input and the handshake runs again, this time reading the
// answer instead of calling.

#include <string>

#include "authnull_async_call.h"

struct AuthnullMfaAnswer {
	int curl_code = -1;      // CURLcode; -1: the call never ran or threw -- a refusal
	long http_code = 0;
	std::string body;
	std::string caller_token; // the proxy's own token it carried (authnull_caller_token.h)
};

using AuthnullMfaCall = AuthnullAsyncCall<AuthnullMfaAnswer>;

// How often a worker thread looks at a session waiting on its push, in microseconds (the unit of
// ProxySQL's mypolls.poll_timeout).
static const unsigned int kAuthnullMfaPollMicros = 100000;

#endif // AUTHNULL_MFA_CALL_H
