// Which policy privileges a client query needs.
//
// A database policy grants a session privileges, and ProxySQL refuses a query that needs one it was
// not granted (checkPermission / checkPermission2). Privileges are SQL verbs -- SELECT, INSERT,
// UPDATE, DELETE, TRUNCATE -- and EXECUTE for everything else; READ, WRITE and EXECUTE are the
// original groups and keep their meaning:
//
//	READ     SELECT
//	WRITE    INSERT, UPDATE, DELETE
//	EXECUTE  EXECUTE, TRUNCATE (TRUNCATE was never WRITE)
//
// so a policy saying SELECT and INSERT can insert and cannot update, where READ and WRITE can do
// both. (authn-service used to collapse SELECT+INSERT into READ+WRITE: custom privileges, AUTH-227.) The classifier that
// decided "needs" looked at the first word of the whole query text, and two queries got a
// READ-only session to write on the lab (2 Nov):
//
//	with d as (insert into t values (1) returning id) select id from d     -- "WITH ... SELECT" = READ
//	select 1; insert into t values (2)                                      -- starts with SELECT
//
// This reads the SQL the way the server does -- strings, quoted identifiers, Postgres dollar quotes
// and nested comments, MySQL backticks, '#' comments and /*! executable comments */ -- splits it
// into statements on the semicolons that are really statement ends, and takes the union of what
// every statement needs. Anything it cannot read to the end (an unterminated string or comment) is
// refused rather than guessed.
//
// Within a statement:
//   SELECT, VALUES, TABLE, SHOW, DESCRIBE, a read-only WITH                          SELECT
//   ... with INSERT / UPDATE / DELETE inside (a writing CTE)                         + that verb
//   ... MERGE inside: INSERT, UPDATE, DELETE; MySQL REPLACE: INSERT, DELETE
//   ... row locks (FOR UPDATE/SHARE, LOCK IN SHARE MODE)                             + UPDATE
//   ... INTO (SELECT INTO creates a table; INTO OUTFILE writes a file)               + EXECUTE
//   EXPLAIN ANALYZE <stmt> runs <stmt>; plain EXPLAIN is SELECT
//   INSERT (with ON CONFLICT DO UPDATE / ON DUPLICATE KEY UPDATE: + UPDATE), UPDATE, DELETE
//   MERGE: the actions it names; REPLACE: INSERT, DELETE; UPSERT: INSERT, UPDATE
//   LOAD, COPY ... FROM                                                              INSERT
//   COPY ... TO STDOUT is an export, SELECT; any other COPY                          EXECUTE
//   TRUNCATE                                                                         TRUNCATE
//   anything else (DDL, GRANT, SET, DO, CALL, BEGIN, ...)                            EXECUTE
// plus, wherever they are called, functions with side effects: setval, nextval, lo_* (UPDATE);
// set_config, dblink_exec, lo_import, pg_terminate_backend, load_file, ... (EXECUTE).
//
// LIMITS. This is a gate in front of the database, not the database's own permission system: a
// user-defined function with side effects reads as a call to an unknown function, which is READ.
// The authoritative control is for the backend connection to use a role that holds only the
// policy's privileges, so that the database refuses what it should; this closes the gaps that
// do not need that.
#ifndef AUTHNULL_QUERY_H
#define AUTHNULL_QUERY_H

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <vector>

enum class AuthnullDialect { Postgres, MySQL };

namespace authnull_query_detail {

enum class TokKind { Word, QuotedIdent, LParen, RParen };

struct Tok {
	TokKind kind;
	std::string text; // Word: upper case; QuotedIdent: lower case
};

inline bool isWordChar(char c) {
	return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}

inline std::string upper(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	return s;
}

inline std::string lower(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

// lex splits sql into statements of tokens. Returns false when a string, identifier or comment is
// not terminated -- the caller refuses such a query.
inline bool lex(const std::string& sql, AuthnullDialect d, std::vector<std::vector<Tok>>& out) {
	const bool pg = d == AuthnullDialect::Postgres;
	const size_t n = sql.size();
	std::vector<Tok> cur;
	bool inExecComment = false; // MySQL /*! ... */: the content is code

	auto endStatement = [&]() {
		out.push_back(cur);
		cur.clear();
	};

	size_t i = 0;
	while (i < n) {
		char c = sql[i];
		char next = i + 1 < n ? sql[i + 1] : '\0';

		if (std::isspace(static_cast<unsigned char>(c))) { i++; continue; }

		// Line comments.
		bool lineComment = false;
		if (c == '-' && next == '-') {
			// MySQL needs whitespace (or the end) after "--"; "1--1" is arithmetic there.
			lineComment = pg || i + 2 >= n || std::isspace(static_cast<unsigned char>(sql[i + 2]));
		} else if (c == '#' && !pg) {
			lineComment = true;
		}
		if (lineComment) {
			while (i < n && sql[i] != '\n') i++;
			continue;
		}

		// Block comments.
		if (c == '/' && next == '*') {
			if (!pg && i + 2 < n && (sql[i + 2] == '!' || sql[i + 2] == '+')) {
				if (sql[i + 2] == '!') { // executable: skip the marker and an optional version number
					i += 3;
					while (i < n && std::isdigit(static_cast<unsigned char>(sql[i]))) i++;
					inExecComment = true;
					continue;
				}
			}
			int depth = 1;
			i += 2;
			while (i < n && depth > 0) {
				if (sql[i] == '*' && i + 1 < n && sql[i + 1] == '/') { depth--; i += 2; continue; }
				if (pg && sql[i] == '/' && i + 1 < n && sql[i + 1] == '*') { depth++; i += 2; continue; }
				i++;
			}
			if (depth > 0) return false;
			continue;
		}
		if (inExecComment && c == '*' && next == '/') {
			inExecComment = false;
			i += 2;
			continue;
		}

		// Postgres dollar quotes: $tag$ ... $tag$ (a $1 parameter is not one).
		if (pg && c == '$') {
			size_t j = i + 1;
			while (j < n && (std::isalnum(static_cast<unsigned char>(sql[j])) || sql[j] == '_')) j++;
			bool tagOk = j < n && sql[j] == '$' &&
				(j == i + 1 || !std::isdigit(static_cast<unsigned char>(sql[i + 1])));
			if (tagOk) {
				std::string tag = sql.substr(i, j - i + 1);
				size_t close = sql.find(tag, j + 1);
				if (close == std::string::npos) return false;
				i = close + tag.size();
				continue;
			}
		}

		// Strings.
		if (c == '\'' || (!pg && c == '"')) {
			// Postgres: backslash escapes only in E'...' strings. MySQL: always.
			bool backslash = !pg;
			if (pg && i > 0 && (sql[i - 1] == 'E' || sql[i - 1] == 'e') &&
				(i == 1 || !isWordChar(sql[i - 2]))) {
				backslash = true;
				if (!cur.empty() && cur.back().kind == TokKind::Word && cur.back().text == "E") cur.pop_back();
			}
			char q = c;
			i++;
			bool closed = false;
			while (i < n) {
				if (backslash && sql[i] == '\\') { i += 2; continue; }
				if (sql[i] == q) {
					if (i + 1 < n && sql[i + 1] == q) { i += 2; continue; }
					i++;
					closed = true;
					break;
				}
				i++;
			}
			if (!closed) return false;
			continue;
		}

		// Quoted identifiers: "name" in Postgres, `name` in MySQL.
		if ((pg && c == '"') || (!pg && c == '`')) {
			char q = c;
			std::string name;
			i++;
			bool closed = false;
			while (i < n) {
				if (sql[i] == q) {
					if (i + 1 < n && sql[i + 1] == q) { name += q; i += 2; continue; }
					i++;
					closed = true;
					break;
				}
				name += sql[i++];
			}
			if (!closed) return false;
			cur.push_back({TokKind::QuotedIdent, lower(name)});
			continue;
		}

		if (c == ';') { endStatement(); i++; continue; }
		if (c == '(') { cur.push_back({TokKind::LParen, "("}); i++; continue; }
		if (c == ')') { cur.push_back({TokKind::RParen, ")"}); i++; continue; }

		if (isWordChar(c)) {
			size_t j = i;
			while (j < n && isWordChar(sql[j])) j++;
			cur.push_back({TokKind::Word, upper(sql.substr(i, j - i))});
			i = j;
			continue;
		}

		i++; // operators and other punctuation
	}
	if (inExecComment) return false;
	endStatement();
	return true;
}

inline bool isWord(const std::vector<Tok>& t, size_t i, const char* w) {
	return i < t.size() && t[i].kind == TokKind::Word && t[i].text == w;
}

inline bool calledAt(const std::vector<Tok>& t, size_t i) {
	return i + 1 < t.size() && t[i + 1].kind == TokKind::LParen;
}

// Functions with side effects, by the privilege calling them needs.
inline const std::set<std::string>& writeFunctions() {
	static const std::set<std::string> s = {
		"setval", "nextval", "lo_unlink", "lo_create", "lo_creat", "lo_from_bytea", "lo_put",
	};
	return s;
}
inline const std::set<std::string>& executeFunctions() {
	static const std::set<std::string> s = {
		// Postgres
		"set_config", "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
		"pg_rotate_logfile", "pg_promote", "pg_switch_wal", "lo_import", "lo_export",
		"dblink", "dblink_exec", "dblink_send_query", "dblink_connect", "dblink_connect_u",
		"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "pg_file_write",
		"query_to_xml", "query_to_xml_and_xmlschema", "query_to_xmlschema",
		"cursor_to_xml", "table_to_xml",
		// MySQL
		"load_file", "sys_exec", "sys_eval",
	};
	return s;
}

inline void addCalls(const std::vector<Tok>& t, std::set<std::string>& need) {
	for (size_t i = 0; i < t.size(); i++) {
		if (!calledAt(t, i)) continue;
		if (t[i].kind != TokKind::Word && t[i].kind != TokKind::QuotedIdent) continue;
		std::string fn = lower(t[i].text);
		if (executeFunctions().count(fn)) need.insert("EXECUTE");
		else if (writeFunctions().count(fn)) need.insert("UPDATE");
	}
}

inline void classify(const std::vector<Tok>& t, std::set<std::string>& need);

// addWrites: the verbs the writes anywhere in t need -- INSERT, UPDATE, DELETE, and MERGE's and
// REPLACE's -- and row locks.
inline void addWrites(const std::vector<Tok>& t, std::set<std::string>& need) {
	for (size_t i = 0; i < t.size(); i++) {
		if (t[i].kind != TokKind::Word || calledAt(t, i)) continue; // REPLACE(...), INSERT(...): string functions
		const std::string& w = t[i].text;
		if (w == "INSERT" || w == "UPDATE" || w == "DELETE") need.insert(w);
		if (w == "MERGE") { need.insert("INSERT"); need.insert("UPDATE"); need.insert("DELETE"); }
		if (w == "REPLACE") { need.insert("INSERT"); need.insert("DELETE"); }
		if (w == "FOR" && (isWord(t, i + 1, "UPDATE") || isWord(t, i + 1, "SHARE") ||
			isWord(t, i + 1, "NO") || isWord(t, i + 1, "KEY"))) {
			need.insert("UPDATE"); // row locks
		}
		if (w == "LOCK" && isWord(t, i + 1, "IN")) need.insert("UPDATE"); // MySQL LOCK IN SHARE MODE
	}
}

// A query statement (SELECT, WITH, VALUES, ...): SELECT, raised by what is inside it.
inline void classifyQuery(const std::vector<Tok>& t, std::set<std::string>& need) {
	need.insert("SELECT");
	addWrites(t, need);
	for (size_t i = 0; i < t.size(); i++) {
		if (t[i].kind != TokKind::Word) continue;
		if (t[i].text == "INTO" && !(i > 0 && t[i - 1].kind == TokKind::Word &&
			(t[i - 1].text == "INSERT" || t[i - 1].text == "REPLACE" || t[i - 1].text == "MERGE"))) {
			need.insert("EXECUTE"); // SELECT INTO creates a table; INTO OUTFILE writes a file
		}
	}
}

inline void classify(const std::vector<Tok>& t, std::set<std::string>& need) {
	size_t first = 0;
	while (first < t.size() && t[first].kind == TokKind::LParen) first++; // "(select ...)"
	if (first >= t.size()) return; // empty statement
	if (t[first].kind != TokKind::Word) { need.insert("EXECUTE"); return; }
	const std::string& k = t[first].text;

	addCalls(t, need);

	if (k == "SELECT" || k == "WITH" || k == "VALUES" || k == "TABLE") {
		classifyQuery(t, need);
		return;
	}
	if (k == "SHOW" || k == "DESCRIBE" || k == "DESC") {
		need.insert("SELECT");
		return;
	}
	if (k == "EXPLAIN") {
		size_t i = first + 1;
		bool analyze = false;
		if (i < t.size() && t[i].kind == TokKind::LParen) { // EXPLAIN (ANALYZE, ...) stmt
			int depth = 0;
			for (; i < t.size(); i++) {
				if (t[i].kind == TokKind::LParen) depth++;
				else if (t[i].kind == TokKind::RParen) { if (--depth == 0) { i++; break; } }
				else if (t[i].kind == TokKind::Word && (t[i].text == "ANALYZE" || t[i].text == "ANALYSE")) analyze = true;
			}
		}
		while (i < t.size() && t[i].kind == TokKind::Word &&
			(t[i].text == "ANALYZE" || t[i].text == "ANALYSE" || t[i].text == "VERBOSE" ||
			 t[i].text == "EXTENDED" || t[i].text == "FORMAT")) {
			if (t[i].text == "ANALYZE" || t[i].text == "ANALYSE") analyze = true;
			i++;
		}
		if (!analyze) { need.insert("SELECT"); return; }
		classify(std::vector<Tok>(t.begin() + static_cast<long>(i), t.end()), need);
		return;
	}
	if (k == "COPY") {
		bool from = false, to = false, stdout_ = false;
		for (const auto& x : t) {
			if (x.kind != TokKind::Word) continue;
			if (x.text == "FROM") from = true;
			if (x.text == "TO") to = true;
			if (x.text == "STDOUT") stdout_ = true;
		}
		if (from) need.insert("INSERT");
		else if (to && stdout_) need.insert("SELECT");
		else need.insert("EXECUTE");
		return;
	}
	if (k == "MERGE") {
		// The actions it names (WHEN ... THEN INSERT / UPDATE / DELETE), not the MERGE word itself.
		for (size_t i = first + 1; i < t.size(); i++) {
			if (t[i].kind == TokKind::Word && (t[i].text == "INSERT" || t[i].text == "UPDATE" || t[i].text == "DELETE") && !calledAt(t, i)) {
				need.insert(t[i].text);
			}
		}
		if (need.empty()) need.insert("UPDATE");
		return;
	}
	if (k == "INSERT" || k == "UPDATE" || k == "DELETE" || k == "REPLACE") {
		addWrites(t, need); // the statement's own verb, an upsert's UPDATE, writes in its CTEs
		return;
	}
	if (k == "UPSERT") { need.insert("INSERT"); need.insert("UPDATE"); return; }
	if (k == "LOAD") { need.insert("INSERT"); return; }
	if (k == "TRUNCATE") { need.insert("TRUNCATE"); return; }
	need.insert("EXECUTE");
}

} // namespace authnull_query_detail

// authnullRequiredPrivileges: the privileges every statement in sql needs, together. ok is false
// when the query could not be read to the end.
inline std::set<std::string> authnullRequiredPrivileges(const std::string& sql, AuthnullDialect d, bool& ok) {
	using namespace authnull_query_detail;
	std::set<std::string> need;
	std::vector<std::vector<Tok>> statements;
	ok = lex(sql, d, statements);
	if (!ok) return need;
	for (const auto& s : statements) classify(s, need);
	return need;
}

// authnullGrantedVerbs: a policy's privileges as the verbs the classifier speaks. The groups expand
// (READ, WRITE, EXECUTE above); a verb is itself; anything else grants nothing.
inline std::set<std::string> authnullGrantedVerbs(const std::vector<std::string>& granted) {
	std::set<std::string> out;
	for (const auto& g : granted) {
		std::string p;
		for (char c : g) {
			if (!std::isspace(static_cast<unsigned char>(c))) p += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
		}
		if (p == "READ") out.insert("SELECT");
		else if (p == "WRITE") { out.insert("INSERT"); out.insert("UPDATE"); out.insert("DELETE"); }
		else if (p == "EXECUTE") { out.insert("EXECUTE"); out.insert("TRUNCATE"); }
		else if (p == "SELECT" || p == "INSERT" || p == "UPDATE" || p == "DELETE" || p == "TRUNCATE") out.insert(p);
	}
	return out;
}

// authnullQueryPermitted: may a session granted these privileges run sql?
inline bool authnullQueryPermitted(const std::vector<std::string>& granted, const std::string& sql, AuthnullDialect d) {
	bool ok = false;
	std::set<std::string> need = authnullRequiredPrivileges(sql, d, ok);
	if (!ok) return false;
	std::set<std::string> have = authnullGrantedVerbs(granted);
	for (const auto& p : need) {
		if (!have.count(p)) return false;
	}
	return true;
}

#endif // AUTHNULL_QUERY_H
