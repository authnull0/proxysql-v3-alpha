// A policy's statement blocklist and row cap.
//
// The login answer's credentialSubject may carry (authnull_login_answer.h):
//
//	blockedCommands  ["DROP", "DELETE", ...]  statement keywords the session may not run
//	blockedPatterns  ["*from customers*", ...] statement texts it may not run; '*' matches any run of
//	                                           characters, case does not matter
//	maxRows          3                         at most this many rows of any result set reach the client
//
// Commands. Every statement of the query (authnull_query.h reads it the way the server does, so a
// comment or a string never hides or fakes one) is refused when its keyword is listed. The keyword
// is the statement's first word, past opening parentheses; for a WITH, the main statement's and each
// CTE body's (WITH d AS (DELETE ...) SELECT ... is a DELETE); for EXPLAIN ANALYZE, EXPLAIN and the
// statement it runs (plain EXPLAIN runs nothing: just EXPLAIN); for PREPARE, PREPARE and the
// statement it prepares (Postgres AS ..., MySQL FROM '...').
//
// Patterns. Each statement, and the whole query, is matched with comments removed, whitespace
// collapsed to single spaces (inside strings too) and trimmed, in lower case. The match is
// a plain wildcard match: each '*'-separated piece is looked for once, left to right, with no
// backtracking, so no pattern can make it slow.
//
// LIMITS. This reads the statement text the client sent. What runs without appearing in it is not
// seen: a function or procedure that drops or deletes (CALL p(), SELECT f()), dynamic SQL (DO $$
// ... $$, EXECUTE in PL/pgSQL, MySQL PREPARE ... FROM @var), triggers and rules. A pattern is text:
// "*from customers*" does not see TABLE customers, "from public.customers" or from "customers".
// The backend role's own grants are the authoritative control.
//
// test/authnull/authnull_blocklist_test.cpp.
#ifndef AUTHNULL_BLOCKLIST_H
#define AUTHNULL_BLOCKLIST_H

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <vector>

#include "authnull_query.h"

struct AuthnullStatementPolicy {
	std::vector<std::string> blocked_commands; // upper case
	std::vector<std::string> blocked_patterns; // lower case, whitespace collapsed
	unsigned long long max_rows = 0;           // 0: no cap
};

namespace authnull_blocklist_detail {

using authnull_query_detail::Tok;
using authnull_query_detail::TokKind;
using authnull_query_detail::isWord;

// collapse: s in lower case, each run of whitespace one space, trimmed.
inline std::string collapse(const std::string& s) {
	std::string out;
	bool space = false;
	for (char c : s) {
		if (std::isspace(static_cast<unsigned char>(c))) { space = true; continue; }
		if (space && !out.empty()) out += ' ';
		space = false;
		out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return out;
}

// closing: the index of the parenthesis closing the one at i, or t.size().
inline size_t closing(const std::vector<Tok>& t, size_t i) {
	int depth = 0;
	for (; i < t.size(); i++) {
		if (t[i].kind == TokKind::LParen) depth++;
		else if (t[i].kind == TokKind::RParen && --depth == 0) return i;
	}
	return t.size();
}

inline std::vector<Tok> slice(const std::vector<Tok>& t, size_t from, size_t to) {
	if (from > t.size()) from = t.size();
	if (to > t.size()) to = t.size();
	if (to < from) to = from;
	return std::vector<Tok>(t.begin() + static_cast<long>(from), t.begin() + static_cast<long>(to));
}

inline void verbs(const std::vector<Tok>& t, AuthnullDialect d, std::set<std::string>& out, int depth = 0);

// verbsOfSQL: the verbs of every statement in sql (a MySQL PREPARE's string).
inline void verbsOfSQL(const std::string& sql, AuthnullDialect d, std::set<std::string>& out, int depth) {
	std::vector<std::vector<Tok>> statements;
	if (!authnull_query_detail::lex(sql, d, statements, true)) return;
	for (const auto& s : statements) verbs(s, d, out, depth + 1);
}

// verbs adds the keywords statement t runs (the header).
inline void verbs(const std::vector<Tok>& t, AuthnullDialect d, std::set<std::string>& out, int depth) {
	if (depth > 32) return;
	size_t i = 0;
	while (i < t.size() && t[i].kind == TokKind::LParen) i++;
	if (i >= t.size() || t[i].kind != TokKind::Word) return;
	if (t[i].text == "WITH") {
		i++;
		if (isWord(t, i, "RECURSIVE")) i++;
		while (i < t.size()) { // name [(columns)] AS [NOT] [MATERIALIZED] (body) [, ...]
			i++;
			if (i < t.size() && t[i].kind == TokKind::LParen) i = closing(t, i) + 1;
			if (!isWord(t, i, "AS")) break;
			i++;
			if (isWord(t, i, "NOT")) i++;
			if (isWord(t, i, "MATERIALIZED")) i++;
			if (i >= t.size() || t[i].kind != TokKind::LParen) break;
			const size_t c = closing(t, i);
			verbs(slice(t, i + 1, c), d, out, depth + 1);
			i = c + 1;
			if (i < t.size() && t[i].kind == TokKind::Punct && t[i].text == ",") { i++; continue; }
			break;
		}
		// Postgres SEARCH / CYCLE clauses come before the main statement.
		if (isWord(t, i, "SEARCH") || isWord(t, i, "CYCLE")) {
			static const std::set<std::string> mains = {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "VALUES", "TABLE", "WITH"};
			while (i < t.size() && !(t[i].kind == TokKind::Word && mains.count(t[i].text))) i++;
		}
		verbs(slice(t, i, t.size()), d, out, depth + 1);
		return;
	}
	const std::string& k = t[i].text;
	out.insert(k);
	if (k == "EXPLAIN") {
		i++;
		bool analyze = false;
		if (i < t.size() && t[i].kind == TokKind::LParen) { // EXPLAIN (ANALYZE, ...) stmt
			const size_t c = closing(t, i);
			for (size_t j = i; j < c; j++) {
				if (isWord(t, j, "ANALYZE") || isWord(t, j, "ANALYSE")) analyze = true;
			}
			i = c + 1;
		}
		while (isWord(t, i, "ANALYZE") || isWord(t, i, "ANALYSE") || isWord(t, i, "VERBOSE") ||
			isWord(t, i, "EXTENDED") || isWord(t, i, "FORMAT")) {
			if (isWord(t, i, "ANALYZE") || isWord(t, i, "ANALYSE")) analyze = true;
			i++;
			if (i < t.size() && t[i].kind == TokKind::Punct && t[i].text == "=") i += 2; // FORMAT=JSON
		}
		if (analyze) verbs(slice(t, i, t.size()), d, out, depth + 1);
		return;
	}
	if (k == "PREPARE") {
		for (size_t j = i + 1; j < t.size(); j++) {
			if (isWord(t, j, "AS")) { verbs(slice(t, j + 1, t.size()), d, out, depth + 1); return; }
			if (isWord(t, j, "FROM") && j + 1 < t.size() && t[j + 1].kind == TokKind::Str) {
				verbsOfSQL(t[j + 1].text, d, out, depth);
				return;
			}
		}
	}
}

// normalize: sql's statements, each with comments removed, whitespace collapsed to single spaces,
// trimmed and in lower case, strings and quoted names included (what looks like a comment in one is
// text). The lexing follows authnull_query.h's lex(); an unterminated string or comment runs to the end.
inline std::vector<std::string> normalize(const std::string& sql, AuthnullDialect d) {
	const bool pg = d == AuthnullDialect::Postgres;
	const size_t n = sql.size();
	std::vector<std::string> out;
	std::string cur;
	bool space = false, inExec = false;
	auto put = [&](char c) {
		if (space && !cur.empty()) cur += ' ';
		space = false;
		cur += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	};
	auto copy = [&](size_t from, size_t to) { // a string or quoted name: its comment markers are text
		for (size_t k = from; k < to && k < n; k++) {
			if (std::isspace(static_cast<unsigned char>(sql[k]))) space = true;
			else put(sql[k]);
		}
	};
	size_t i = 0;
	while (i < n) {
		const char c = sql[i];
		const char next = i + 1 < n ? sql[i + 1] : '\0';
		if (std::isspace(static_cast<unsigned char>(c))) { space = true; i++; continue; }
		bool line = false;
		if (c == '-' && next == '-') line = pg || i + 2 >= n || std::isspace(static_cast<unsigned char>(sql[i + 2]));
		else if (c == '#' && !pg) line = true;
		if (line) {
			while (i < n && sql[i] != '\n') i++;
			space = true;
			continue;
		}
		if (c == '/' && next == '*') {
			if (!pg && i + 2 < n && sql[i + 2] == '!') { // executable comment: the content is code
				i += 3;
				while (i < n && std::isdigit(static_cast<unsigned char>(sql[i]))) i++;
				inExec = true;
				space = true;
				continue;
			}
			int depth = 1;
			i += 2;
			while (i < n && depth > 0) {
				if (sql[i] == '*' && i + 1 < n && sql[i + 1] == '/') { depth--; i += 2; continue; }
				if (pg && sql[i] == '/' && i + 1 < n && sql[i + 1] == '*') { depth++; i += 2; continue; }
				i++;
			}
			space = true;
			continue;
		}
		if (inExec && c == '*' && next == '/') { inExec = false; i += 2; space = true; continue; }
		if (pg && c == '$') {
			size_t j = i + 1;
			while (j < n && (std::isalnum(static_cast<unsigned char>(sql[j])) || sql[j] == '_')) j++;
			if (j < n && sql[j] == '$' && (j == i + 1 || !std::isdigit(static_cast<unsigned char>(sql[i + 1])))) {
				const std::string tag = sql.substr(i, j - i + 1);
				const size_t endq = sql.find(tag, j + 1);
				const size_t to = endq == std::string::npos ? n : endq + tag.size();
				copy(i, to);
				i = to;
				continue;
			}
		}
		if (c == '\'' || c == '"' || (!pg && c == '`')) {
			const bool backslash = (c != '`' && !pg) ||
				(pg && c == '\'' && i > 0 && (sql[i - 1] == 'E' || sql[i - 1] == 'e') &&
				 (i == 1 || !authnull_query_detail::isWordChar(sql[i - 2])));
			size_t j = i + 1;
			while (j < n) {
				if (backslash && sql[j] == '\\') { j += 2; continue; }
				if (sql[j] == c) {
					if (j + 1 < n && sql[j + 1] == c) { j += 2; continue; }
					j++;
					break;
				}
				j++;
			}
			copy(i, j);
			i = j;
			continue;
		}
		if (c == ';') {
			if (!cur.empty()) out.push_back(cur);
			cur.clear();
			space = false;
			i++;
			continue;
		}
		put(c);
		i++;
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

} // namespace authnull_blocklist_detail

// authnullWildcardMatch: does text match pattern, '*' matching any run of characters (none too)?
// Both are compared as given (the callers lower-case them). Each piece between stars is searched
// once, left to right: the leftmost place it fits leaves the most room for the rest.
inline bool authnullWildcardMatch(const std::string& pattern, const std::string& text) {
	size_t star = pattern.find('*');
	if (star == std::string::npos) return pattern == text;
	if (text.compare(0, star, pattern, 0, star) != 0 || text.size() < star) return false;
	size_t at = star;       // in text: what the pieces so far used up
	size_t p = star + 1;    // in pattern: the next piece
	for (;;) {
		star = pattern.find('*', p);
		const size_t len = (star == std::string::npos ? pattern.size() : star) - p;
		if (star == std::string::npos) { // the last piece ends the text
			return text.size() >= at + len && text.compare(text.size() - len, len, pattern, p, len) == 0;
		}
		if (len > 0) {
			const size_t f = text.find(pattern.c_str() + p, at, len);
			if (f == std::string::npos) return false;
			at = f + len;
		}
		p = star + 1;
	}
}

// authnullPolicyCommand / authnullPolicyPattern: a blockedCommands / blockedPatterns entry as it is
// kept: the keyword in upper case without spaces; the pattern collapsed and in lower case.
inline std::string authnullPolicyCommand(const std::string& s) {
	std::string out;
	for (char c : s) {
		if (!std::isspace(static_cast<unsigned char>(c))) out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	return out;
}
inline std::string authnullPolicyPattern(const std::string& s) { return authnull_blocklist_detail::collapse(s); }

// authnullBlockedRule: the rule of the policy sql breaks -- the keyword ("DROP") or the pattern
// ("pattern *from customers*") -- or "" when it breaks none. A query that cannot be read to its end
// is left to the privilege check, which refuses it (authnull_query.h).
inline std::string authnullBlockedRule(const AuthnullStatementPolicy& p, const std::string& sql, AuthnullDialect d) {
	using namespace authnull_blocklist_detail;
	if (!p.blocked_commands.empty()) {
		std::vector<std::vector<Tok>> statements;
		if (authnull_query_detail::lex(sql, d, statements, true)) {
			std::set<std::string> found;
			for (const auto& s : statements) verbs(s, d, found);
			for (const auto& c : p.blocked_commands) {
				if (!c.empty() && found.count(c)) return c;
			}
		}
	}
	if (!p.blocked_patterns.empty()) {
		std::vector<std::string> texts = normalize(sql, d);
		if (texts.size() > 1) {
			std::string whole;
			for (const auto& s : texts) whole += (whole.empty() ? "" : "; ") + s;
			texts.push_back(whole);
		}
		for (const auto& pat : p.blocked_patterns) {
			if (pat.empty()) continue;
			for (const auto& s : texts) {
				if (authnullWildcardMatch(pat, s)) return "pattern " + pat;
			}
		}
	}
	return "";
}

// authnullBlockedMessage: the client's error for a statement refused by rule.
inline std::string authnullBlockedMessage(const std::string& rule) {
	return "Access denied: blocked by policy (" + rule + ")";
}

// authnullCappedTag: a Postgres CommandComplete tag once the row cap held its result set to rows:
// "SELECT 10" -> "SELECT 3", "FETCH 10" -> "FETCH 3". Any other tag is the server's (an UPDATE ...
// RETURNING still updated what it says).
inline std::string authnullCappedTag(const std::string& tag, unsigned long long rows) {
	for (const char* verb : {"SELECT ", "FETCH "}) {
		const size_t len = std::char_traits<char>::length(verb);
		if (tag.compare(0, len, verb) == 0 && tag.size() > len &&
			std::all_of(tag.begin() + static_cast<long>(len), tag.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; })) {
			return std::string(verb) + std::to_string(rows);
		}
	}
	return tag;
}

// authnullCappedNotice: the text of the notice a capped result set ends with.
inline std::string authnullCappedNotice(unsigned long long max_rows) {
	return "result capped at " + std::to_string(max_rows) + " rows by policy";
}

#endif // AUTHNULL_BLOCKLIST_H
