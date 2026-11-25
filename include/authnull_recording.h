#ifndef AUTHNULL_RECORDING_H
#define AUTHNULL_RECORDING_H

// Database session recording (authnull-service docs/DB-SESSION-RECORDING.md).
//
// A session whose policy says actions.session.record (credentialSubject.session.record, from
// authn-service) has every statement written here: its text with secrets masked, whether ProxySQL
// let it through, rows sent and affected, duration, and the error if any -- never result data. The
// lines go to a local spool, one file per 5-second bucket in a private directory, which the
// database agent ships to the backend and deletes; it takes only buckets that have closed.
//
// Masking: a quoted value right after PASSWORD (also PASSWORD =, PASSWORD FOR x =, PASSWORD(...))
// or IDENTIFIED BY becomes '***'; strings, quoted identifiers and comments are read as the server
// reads them, so the word inside a string is not a keyword. Statements are bounded.
// test/authnull/authnull_recording_test.cpp.

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../deps/json/json.hpp"

static const size_t kAuthnullRecordMaxStatement = 4096;

namespace authnull_recording_detail {

inline bool wordChar(char c) {
	return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}

inline std::string upper(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	return s;
}

// endOfDollarQuote: given s[i] == '$', the index past the dollar-quoted string starting there, or
// npos when it is not one.
inline size_t endOfDollarQuote(const std::string& s, size_t i) {
	size_t j = i + 1;
	while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_')) j++;
	if (j >= s.size() || s[j] != '$') return std::string::npos;
	std::string tag = s.substr(i, j - i + 1);
	size_t close = s.find(tag, j + 1);
	return close == std::string::npos ? s.size() : close + tag.size();
}

} // namespace authnull_recording_detail

// authnullMaskSecrets returns sql with the secrets it carries masked, and bounded.
inline std::string authnullMaskSecrets(const std::string& sql) {
	namespace d = authnull_recording_detail;
	std::string out;
	out.reserve(sql.size());
	int pending = 0;           // tokens left in which a string literal is a secret
	std::string prevWord;
	const int window = 5;
	size_t i = 0;
	while (i < sql.size()) {
		char c = sql[i];
		if (std::isspace(static_cast<unsigned char>(c))) { out += c; i++; continue; }
		if (c == '-' && i + 1 < sql.size() && sql[i + 1] == '-') { // line comment
			size_t e = sql.find('\n', i);
			e = (e == std::string::npos) ? sql.size() : e;
			out.append(sql, i, e - i);
			i = e;
			continue;
		}
		if (c == '/' && i + 1 < sql.size() && sql[i + 1] == '*') { // block comment
			size_t e = sql.find("*/", i + 2);
			e = (e == std::string::npos) ? sql.size() : e + 2;
			out.append(sql, i, e - i);
			i = e;
			continue;
		}
		if (c == '\'') { // string literal, '' escapes
			size_t j = i + 1;
			while (j < sql.size()) {
				if (sql[j] == '\'') {
					if (j + 1 < sql.size() && sql[j + 1] == '\'') { j += 2; continue; }
					break;
				}
				j++;
			}
			size_t e = (j < sql.size()) ? j + 1 : sql.size();
			if (pending > 0) { out += "'***'"; pending = 0; }
			else out.append(sql, i, e - i);
			i = e;
			continue;
		}
		if (c == '"') { // quoted identifier
			size_t e = sql.find('"', i + 1);
			e = (e == std::string::npos) ? sql.size() : e + 1;
			out.append(sql, i, e - i);
			i = e;
			if (pending > 0) pending--;
			continue;
		}
		if (c == '$') {
			size_t e = d::endOfDollarQuote(sql, i);
			if (e != std::string::npos) {
				if (pending > 0) { out += "'***'"; pending = 0; }
				else out.append(sql, i, e - i);
				i = e;
				continue;
			}
		}
		if (d::wordChar(c)) {
			size_t j = i;
			while (j < sql.size() && d::wordChar(sql[j])) j++;
			std::string w = d::upper(sql.substr(i, j - i));
			out.append(sql, i, j - i);
			i = j;
			if (w == "PASSWORD" || (w == "BY" && prevWord == "IDENTIFIED")) {
				pending = window;
			} else if (pending > 0) {
				pending--;
			}
			prevWord = w;
			continue;
		}
		// punctuation
		out += c;
		i++;
		if (c == ',' || c == ';' || c == ')') pending = 0;
		else if (pending > 0 && c != '(' && c != '=') pending--;
	}
	if (out.size() > kAuthnullRecordMaxStatement) out = out.substr(0, kAuthnullRecordMaxStatement) + "...";
	return out;
}

namespace authnull_recording_detail {

// maskQuoted: every quoted run becomes '***'. A quote right after a letter or digit is an
// apostrophe ("doesn't"), not a value.
inline std::string maskQuoted(const std::string& msg) {
	std::string out;
	out.reserve(msg.size());
	size_t i = 0;
	while (i < msg.size()) {
		char c = msg[i];
		bool opens = c == '\'' && (i == 0 || !std::isalnum(static_cast<unsigned char>(msg[i - 1])));
		if (!opens) {
			out += c;
			i++;
			continue;
		}
		size_t j = i + 1;
		while (j < msg.size()) {
			if (msg[j] == '\'') {
				if (j + 1 < msg.size() && msg[j + 1] == '\'') { j += 2; continue; }
				break;
			}
			j++;
		}
		out += "'***'";
		i = (j < msg.size()) ? j + 1 : msg.size();
	}
	return out;
}

} // namespace authnull_recording_detail

// authnullMaskErrorValues hides the values a MySQL error message (code, message) quotes and keeps
// the names, which say what went wrong. PostgreSQL keeps such values in DETAIL, which is never
// recorded; MySQL has only the one message.
//   - Names only, kept as they are: 1044, 1045 access denied for user (to database); 1048 column
//     cannot be null; 1049 unknown database; 1050, 1051 table exists / unknown; 1054 unknown column;
//     1060, 1061 duplicate column / key name; 1091 can't drop; 1109 unknown table; 1142 command
//     denied; 1146 table doesn't exist; 1305 does not exist; 1356 view invalid; 1364 no default;
//     1406 data too long for column.
//   - A value, masked, and names, kept: 1062 "Duplicate entry '<value>' for key 'k'"; 1292, 1366
//     "Incorrect <type> value: '<value>' for column 'c' at row n" (1292 also "Truncated incorrect
//     <type> value: '<value>'"); 1064 "... near '<SQL>' at line n". The value runs from the
//     lead-in to the last tail, so a quote inside it ("O'Brien") does not end it.
//   - Any other code, or one of these in a shape not recognised: every quoted run is masked.
inline std::string authnullMaskErrorValues(int code, const std::string& msg) {
	static const std::set<int> namesOnly = {
		1044, 1045, 1048, 1049, 1050, 1051, 1054, 1060, 1061, 1091, 1109, 1142, 1146, 1305, 1356, 1364, 1406,
	};
	if (namesOnly.count(code)) return msg;
	std::string lead, tail;
	if (code == 1062) { lead = "Duplicate entry '"; tail = "' for key '"; }
	else if (code == 1064) { lead = "near '"; tail = "' at line "; }
	else if (code == 1292 || code == 1366) {
		lead = "value: '";
		tail = msg.find("' for column '") != std::string::npos ? "' for column '" : "'";
	}
	if (!lead.empty()) {
		size_t a = msg.find(lead);
		size_t b = a == std::string::npos ? std::string::npos : msg.rfind(tail);
		if (b != std::string::npos && b >= a + lead.size()) return msg.substr(0, a + lead.size()) + "***" + msg.substr(b);
	}
	return authnull_recording_detail::maskQuoted(msg);
}

// authnullRecordFromJSON: whether the policy asks for the session to be recorded
// (credentialSubject.session.record, a boolean).
inline bool authnullRecordFromJSON(const nlohmann::json& cs) {
	if (!cs.is_object() || !cs.contains("session") || !cs["session"].is_object()) return false;
	const nlohmann::json& s = cs["session"];
	return s.contains("record") && s["record"].is_boolean() && s["record"].get<bool>();
}

// AuthnullRecordedStatement is one statement of a recorded session.
struct AuthnullRecordedStatement {
	unsigned long long session_id = 0;
	long long at_ms = 0;         // when it started, Unix milliseconds
	long long duration_ms = 0;
	std::string user;            // as ProxySQL connects: the policy's role or its restricted role
	std::string database;
	std::string client;
	int hostgroup = -1;          // the server it ran on; the agent uploads it as that server's
	std::string engine;          // "mysql" or "postgres": ProxySQL numbers each engine's hostgroups separately
	std::string statement;       // as received; authnullRecordLine masks it
	bool allowed = true;         // false: ProxySQL refused it
	unsigned long long rows = 0;
	unsigned long long affected = 0;
	std::string error;
	bool capped = false;         // the policy's row cap cut a result set short (authnull_blocklist.h)
};

// authnullRecordLine is the statement as one JSON line (no newline).
inline std::string authnullRecordLine(const AuthnullRecordedStatement& s) {
	nlohmann::json j = {
		{"sid", s.session_id}, {"at", s.at_ms}, {"durMs", s.duration_ms}, {"user", s.user}, {"db", s.database},
		{"client", s.client}, {"stmt", authnullMaskSecrets(s.statement)}, {"allowed", s.allowed},
		{"rows", s.rows}, {"affected", s.affected}, {"hg", s.hostgroup}, {"engine", s.engine},
	};
	if (!s.error.empty()) j["error"] = s.error.size() > 500 ? s.error.substr(0, 500) : s.error;
	if (s.capped) j["capped"] = true;
	return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

// AuthnullRecorder appends lines to the spool: <dir>/<bucket>.jsonl, a bucket being 5 seconds.
class AuthnullRecorder {
public:
	AuthnullRecorder(std::string dir, std::function<long long()> clock) : dir_(std::move(dir)), clock_(std::move(clock)) {}
	~AuthnullRecorder() {
		if (fd_ >= 0) close(fd_);
	}

	bool append(const std::string& line) {
		std::lock_guard<std::mutex> lock(mu_);
		long long bucket = clock_() / 5 * 5;
		if (bucket != bucket_ || fd_ < 0) {
			if (fd_ >= 0) { close(fd_); fd_ = -1; }
			if (mkdir(dir_.c_str(), 0700) != 0 && errno != EEXIST) return false;
			chmod(dir_.c_str(), 0700);
			std::string path = dir_ + "/" + std::to_string(bucket) + ".jsonl";
			fd_ = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
			if (fd_ < 0) return false;
			fchmod(fd_, 0600);
			bucket_ = bucket;
		}
		std::string l = line + "\n";
		const char* p = l.data();
		size_t left = l.size();
		while (left > 0) {
			ssize_t n = write(fd_, p, left);
			if (n < 0) {
				if (errno == EINTR) continue;
				return false;
			}
			p += n;
			left -= static_cast<size_t>(n);
		}
		return true;
	}

private:
	std::string dir_;
	std::function<long long()> clock_;
	std::mutex mu_;
	int fd_ = -1;
	long long bucket_ = -1;
};

// authnullRecorder is the process's recorder: AUTHNULL_RECORDING_DIR, or
// /var/lib/proxysql/authnull-recordings.
inline AuthnullRecorder& authnullRecorder() {
	static AuthnullRecorder r([] {
		const char* d = std::getenv("AUTHNULL_RECORDING_DIR");
		return std::string(d && *d ? d : "/var/lib/proxysql/authnull-recordings");
	}(), [] { return static_cast<long long>(time(nullptr)); });
	return r;
}

#endif // AUTHNULL_RECORDING_H
