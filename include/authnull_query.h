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
//   LOAD, COPY ... FROM a server file                                                INSERT
//   COPY ... TO STDOUT / FROM STDIN (streams through the proxy, which cannot relay it) COPY_STREAM
//   any other COPY                                                                   EXECUTE
//   TRUNCATE                                                                         TRUNCATE
//   client housekeeping (below)                                                      nothing
//   anything else (DDL, GRANT, DO, CALL, SET ROLE, ...)                              EXECUTE
// plus, wherever they are called, functions with side effects: setval, nextval, lo_* (UPDATE);
// set_config, dblink_exec, lo_import, pg_terminate_backend, load_file, ... (EXECUTE).
//
// Client housekeeping needs no privilege: what pgAdmin, DBeaver and the drivers send on their own
// to set up a connection. Transactions (BEGIN / START TRANSACTION, COMMIT, END, ROLLBACK, ABORT,
// SAVEPOINT, RELEASE -- not their PREPARED forms); on Postgres, SET / RESET of the settings clients
// use (clientSettings: DateStyle, TimeZone, search_path, ...) and set_config of one written out,
// SET TRANSACTION, SET SESSION CHARACTERISTICS, SET CONSTRAINTS, DISCARD, DEALLOCATE [PREPARE] ALL
// (not DEALLOCATE <name>); on MySQL, SET of session
// and user variables, SET NAMES, SET TRANSACTION, USE. Still EXECUTE: what changes who the session
// is or reaches past it -- SET ROLE, SESSION AUTHORIZATION, any other Postgres setting (e.g.
// default_transaction_read_only), MySQL SET GLOBAL / PERSIST / PASSWORD / ROLE / DEFAULT ROLE /
// RESOURCE GROUP. Whatever a SET reads or calls still counts (SET @n = (SELECT ...): SELECT).
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

enum class TokKind { Word, QuotedIdent, LParen, RParen, Str, Punct };

struct Tok {
	TokKind kind;
	std::string text; // Word: upper case; QuotedIdent and Str: lower case
	bool dquoted = false; // a MySQL Str written "..." (a column name under ANSI_QUOTES)
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
// not terminated -- the caller refuses such a query. Other punctuation (, . = * ...) is dropped,
// or kept as Punct tokens when punct is set (field masking: "amount, status" is not an alias).
inline bool lex(const std::string& sql, AuthnullDialect d, std::vector<std::vector<Tok>>& out, bool punct = false) {
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
			std::string text;
			i++;
			bool closed = false;
			while (i < n) {
				if (backslash && sql[i] == '\\') { if (i + 1 < n) text += sql[i + 1]; i += 2; continue; }
				if (sql[i] == q) {
					if (i + 1 < n && sql[i + 1] == q) { text += q; i += 2; continue; }
					i++;
					closed = true;
					break;
				}
				text += sql[i++];
			}
			if (!closed) return false;
			cur.push_back({TokKind::Str, lower(text), q == '"'});
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

		if (punct) cur.push_back({TokKind::Punct, std::string(1, c)});
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

// Postgres settings clients set up a connection with: SET / RESET of these, and set_config of one
// written out, need no privilege. Any other setting stays EXECUTE (role, session_authorization,
// default_transaction_read_only, ...): it is not housekeeping.
inline const std::set<std::string>& clientSettings() {
	static const std::set<std::string> s = {
		"datestyle", "intervalstyle", "timezone", "client_encoding", "client_min_messages",
		"application_name", "search_path", "extra_float_digits", "bytea_output",
		"statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "idle_session_timeout",
		"standard_conforming_strings", "escape_string_warning", "transaction_isolation",
		"default_transaction_isolation", "lc_monetary", "lc_numeric", "lc_time", "timezone_abbreviations",
		"xmloption", "xmlbinary", "names",
	};
	return s;
}

inline void addCalls(const std::vector<Tok>& t, std::set<std::string>& need) {
	for (size_t i = 0; i < t.size(); i++) {
		if (!calledAt(t, i)) continue;
		if (t[i].kind != TokKind::Word && t[i].kind != TokKind::QuotedIdent) continue;
		std::string fn = lower(t[i].text);
		// set_config('DateStyle', ...): housekeeping when the setting is written out and a client one.
		if (fn == "set_config" && i + 2 < t.size() && t[i + 2].kind == TokKind::Str &&
			clientSettings().count(t[i + 2].text)) continue;
		if (executeFunctions().count(fn)) need.insert("EXECUTE");
		else if (writeFunctions().count(fn)) need.insert("UPDATE");
	}
}

inline void classify(const std::vector<Tok>& t, AuthnullDialect d, std::set<std::string>& need);

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

inline bool anyWord(const std::vector<Tok>& t, size_t from, const std::set<std::string>& words) {
	for (size_t i = from; i < t.size(); i++) {
		if (t[i].kind == TokKind::Word && words.count(t[i].text)) return true;
	}
	return false;
}

inline bool onlyWords(const std::vector<Tok>& t, size_t from, const std::set<std::string>& words) {
	for (size_t i = from; i < t.size(); i++) {
		if (t[i].kind != TokKind::Word || !words.count(t[i].text)) return false;
	}
	return true;
}

// classifyHousekeeping: when t is client housekeeping (the header), adds what it needs -- nothing,
// or what a SET reads or calls -- and returns true. Anything else returns false and is classified
// as before.
inline bool classifyHousekeeping(const std::vector<Tok>& t, size_t first, AuthnullDialect d, std::set<std::string>& need);

inline void classify(const std::vector<Tok>& t, AuthnullDialect d, std::set<std::string>& need) {
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
		classify(std::vector<Tok>(t.begin() + static_cast<long>(i), t.end()), d, need);
		return;
	}
	if (k == "COPY") {
		bool from = false, stream = false;
		for (const auto& x : t) {
			if (x.kind != TokKind::Word) continue;
			if (x.text == "FROM") from = true;
			if (x.text == "STDOUT" || x.text == "STDIN") stream = true;
		}
		// The proxy cannot relay the COPY sub-protocol: the backend connection asserts on it
		// (PgSQL_Connection.cpp, PGRES_COPY_*), which took the whole proxy down for any user allowed
		// to SELECT. A COPY through the connection needs a privilege no policy grants.
		if (stream) need.insert("COPY_STREAM");
		else if (from) need.insert("INSERT");
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
	if (classifyHousekeeping(t, first, d, need)) return;
	if (k == "UPSERT") { need.insert("INSERT"); need.insert("UPDATE"); return; }
	if (k == "LOAD") { need.insert("INSERT"); return; }
	if (k == "TRUNCATE") { need.insert("TRUNCATE"); return; }
	need.insert("EXECUTE");
}

inline bool classifyHousekeeping(const std::vector<Tok>& t, size_t first, AuthnullDialect d, std::set<std::string>& need) {
	const bool pg = d == AuthnullDialect::Postgres;
	const std::string& k = t[first].text;
	const size_t rest = first + 1;
	static const std::set<std::string> txModes = {
		"WORK", "TRANSACTION", "ISOLATION", "LEVEL", "READ", "WRITE", "ONLY", "COMMITTED", "UNCOMMITTED",
		"REPEATABLE", "SERIALIZABLE", "DEFERRABLE", "NOT", "WITH", "CONSISTENT", "SNAPSHOT",
	};

	// Transactions. BEGIN and START only with transaction modes after them: BEGIN ATOMIC / NOT
	// ATOMIC opens a block of statements, not a transaction.
	if (k == "BEGIN") return onlyWords(t, rest, txModes);
	if (k == "START") return isWord(t, rest, "TRANSACTION") && onlyWords(t, rest + 1, txModes);
	if (k == "COMMIT" || k == "END" || k == "ROLLBACK" || k == "ABORT") {
		return !anyWord(t, rest, {"PREPARED"}); // ... PREPARED finishes a two-phase transaction
	}
	if (k == "SAVEPOINT" || k == "RELEASE") return true;
	if (!pg && k == "USE") return true;
	if (pg && k == "DISCARD") return true;
	// DEALLOCATE ALL drops only what DISCARD ALL drops too, and psycopg 3 (pgAdmin 4) sends it on its
	// own after ROLLBACK, DISCARD ALL, DROP or ALTER once it holds a prepared statement.
	if (pg && k == "DEALLOCATE") {
		const size_t i = isWord(t, rest, "PREPARE") ? rest + 1 : rest;
		return isWord(t, i, "ALL") && i + 1 == t.size();
	}
	if (pg && k == "RESET") {
		if (isWord(t, rest, "ALL")) return true;
		if (rest < t.size() && t[rest].kind == TokKind::Word && clientSettings().count(lower(t[rest].text))) return true;
		return false;
	}
	if (k != "SET") return false;

	size_t i = rest;
	if (pg) {
		if (isWord(t, i, "SESSION") || isWord(t, i, "LOCAL")) {
			if (isWord(t, i, "SESSION") && isWord(t, i + 1, "CHARACTERISTICS")) return true;
			i++;
		}
		if (isWord(t, i, "TRANSACTION") || isWord(t, i, "CONSTRAINTS")) return true;
		if (isWord(t, i, "TIME") && isWord(t, i + 1, "ZONE")) return true;
		// SET <setting> = / TO ...: only the settings clients use. ROLE, SESSION AUTHORIZATION and
		// everything else fall through to EXECUTE.
		if (i < t.size() && (t[i].kind == TokKind::Word || t[i].kind == TokKind::QuotedIdent) &&
			clientSettings().count(lower(t[i].text))) return true;
		return false;
	}

	// MySQL. Server-wide, persistent, or about who the session is: EXECUTE, as before.
	if (anyWord(t, rest, {"GLOBAL", "PERSIST", "PERSIST_ONLY"})) return false;
	if (isWord(t, i, "PASSWORD") || isWord(t, i, "ROLE") || isWord(t, i, "RESOURCE") ||
		(isWord(t, i, "DEFAULT") && isWord(t, i + 1, "ROLE"))) return false;
	// Session and user variables, NAMES, TRANSACTION: nothing of their own; a read or a lock
	// inside (SET @n = (SELECT ...)) counts as it would anywhere.
	if (anyWord(t, rest, {"SELECT", "WITH", "VALUES", "TABLE"})) classifyQuery(t, need);
	else addWrites(t, need);
	return true;
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
	for (const auto& s : statements) classify(s, d, need);
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
