#ifndef AUTHNULL_CURL_CANCEL_H
#define AUTHNULL_CURL_CANCEL_H

// Dropping the push-MFA login call when the client is gone (authnull_async_call.h, cancel()).
//
// The call to authn-service blocks until the person answers the push, up to 90 s. A client that
// hangs up in the meantime used to leave the request open: the person could still approve, and
// authn-service, which sees only the proxy's connection, logged an access that never happened.
// With authnullCurlCancelOn, curl checks the call's cancel flag while it waits -- libcurl calls the
// check about once a second when no data moves -- and gives up as soon as it is raised
// (CURLE_ABORTED_BY_CALLBACK). Closing the connection is what tells authn-service nobody is waiting.
// test/authnull/authnull_curl_cancel_test.cpp.

#include <curl/curl.h>

#include <atomic>

inline int authnullCurlCancelCheck(void* flag, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
	return static_cast<const std::atomic<bool>*>(flag)->load() ? 1 : 0; // non-zero: curl aborts
}

// authnullCurlCancelOn makes the transfer on curl stop once *cancelled is true. cancelled must live
// until the transfer is over (it does: it is the flag of the call that makes the transfer).
inline void authnullCurlCancelOn(CURL* curl, const std::atomic<bool>* cancelled) {
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, authnullCurlCancelCheck);
	curl_easy_setopt(curl, CURLOPT_XFERINFODATA, const_cast<std::atomic<bool>*>(cancelled));
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
}

#endif // AUTHNULL_CURL_CANCEL_H
