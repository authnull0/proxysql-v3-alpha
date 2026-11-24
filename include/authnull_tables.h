// Which tables a MySQL statement names, held to a policy's table list.
//
// A database policy may list the tables it grants (credentialSubject.tables). The privilege check
// (authnull_query.h) looks only at SQL verbs, so on the lab a session under tables=[orders] read
// customers -- plainly, as dbmfa_test.customers and through a JOIN -- and only MySQL's own grants
// stopped it. When the list is not empty, every table a statement names must be on it:
//
//   SELECT / WITH / TABLE / VALUES: FROM lists -- JOINs of every kind, comma joins, parenthesised
//     joins, derived tables (whose alias is not a table) and their subqueries; TABLE t
//   INSERT / REPLACE [INTO] t, UPDATE t1 [, t2 | JOIN ...], DELETE FROM t, multi-table DELETE
//     (its targets must be among its FROM / USING tables, which MySQL enforces, so those are read)
//   TRUNCATE [TABLE] t, DESCRIBE / DESC / EXPLAIN t (EXPLAIN <statement> reads the statement)
//   SHOW COLUMNS / FIELDS / INDEX / INDEXES / KEYS FROM t [FROM db], SHOW CREATE TABLE / VIEW t
//   a subquery anywhere (WHERE, SELECT list, ON, SET, VALUES): its own FROM list
// A CTE's name is not a table where the CTE is in scope: from the end of its body (from its name
// under WITH RECURSIVE) to the end of the query it belongs to.
//
// A name is compared case-insensitively. db.t must be in the session's database, except that
// information_schema is metadata every tool reads and is allowed; mysql, performance_schema and sys
// are refused. A list entry may be "t" or "<session db>.t".
//
// Statements that name no table pass: SELECT without FROM (SELECT @@version, SELECT DATABASE()),
// SHOW TABLES / DATABASES / VARIABLES / STATUS / ..., SET (whose subqueries are read like any
// other), and client housekeeping (BEGIN, COMMIT, USE, ...: authnull_query.h). Anything else --
// DDL, CALL, DO, HANDLER, LOAD, LOCK TABLES, PREPARE / EXECUTE, ... -- and anything this cannot read
// with confidence is refused.
//
// LIMITS. This reads names, not what they stand for: a view or stored function on the list that
// reads another table, a trigger, and SQL built at run time (PREPARE ... FROM @sql) are beyond it.
// The authoritative control is a backend account granted only the listed tables.
// test/authnull/authnull_tables_test.cpp.
#ifndef AUTHNULL_TABLES_H
#define AUTHNULL_TABLES_H

#include "authnull_query.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace authnull_tables_detail {

using authnull_query_detail::Tok;
using authnull_query_detail::TokKind;
using authnull_query_detail::isWord;
using authnull_query_detail::lower;

using Ref = std::pair<std::string, std::string>; // {db (empty: the session's), table}, lower case

const size_t npos = static_cast<size_t>(-1);

struct Scan {
	const std::vector<Tok>& t;
	std::vector<Ref>& refs;
	bool ok = true;
	int depth = 0;
	struct Cte { std::string name; int depth; size_t from; };
	std::vector<Cte> ctes;    // CTEs in scope, innermost last
	std::vector<bool> joined; // JOIN tokens a table list read
	Scan(const std::vector<Tok>& t_, std::vector<Ref>& r) : t(t_), refs(r), joined(t_.size(), false) {}
	bool fail() { ok = false; return false; }
};

inline bool isPunct(const std::vector<Tok>& t, size_t i, const char* p) {
	return i < t.size() && t[i].kind == TokKind::Punct && t[i].text == p;
}
inline bool isKind(const std::vector<Tok>& t, size_t i, TokKind k) { return i < t.size() && t[i].kind == k; }
inline bool isName(const std::vector<Tok>& t, size_t i) {
	return isKind(t, i, TokKind::Word) || isKind(t, i, TokKind::QuotedIdent);
}
inline bool anyOf(const std::vector<Tok>& t, size_t i, const std::set<std::string>& words) {
	return isKind(t, i, TokKind::Word) && words.count(t[i].text);
}

// close: the RParen matching the LParen at i, or npos.
inline size_t close(const std::vector<Tok>& t, size_t i) {
	int d = 0;
	for (; i < t.size(); i++) {
		if (t[i].kind == TokKind::LParen) d++;
		else if (t[i].kind == TokKind::RParen && --d == 0) return i;
	}
	return npos;
}

// What may follow a table reference and is therefore not its alias.
inline const std::set<std::string>& listEnds() {
	static const std::set<std::string> s = {
		"WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "WINDOW", "UNION", "INTERSECT", "EXCEPT", "FOR",
		"LOCK", "INTO", "SET", "PROCEDURE",
	};
	return s;
}
inline const std::set<std::string>& joinWords() {
	static const std::set<std::string> s = {"INNER", "LEFT", "RIGHT", "CROSS", "NATURAL", "OUTER"};
	return s;
}
inline bool notAlias(const std::string& w) {
	static const std::set<std::string> s = {
		"AS", "ON", "USING", "JOIN", "STRAIGHT_JOIN", "PARTITION", "USE", "IGNORE", "FORCE",
	};
	return s.count(w) || listEnds().count(w) || joinWords().count(w);
}
inline const std::set<std::string>& queryStarts() {
	static const std::set<std::string> s = {"SELECT", "WITH", "VALUES", "TABLE"};
	return s;
}

// record notes a table reference, unless it is a CTE in scope.
inline void record(Scan& s, size_t at, const std::string& db, const std::string& name) {
	if (db.empty()) {
		for (const auto& c : s.ctes) {
			if (c.name == name && c.from <= at) return;
		}
	}
	s.refs.push_back({db, name});
}

// tableName reads [db.]name at i into db / name and returns the index after it, or npos.
inline size_t tableName(const std::vector<Tok>& t, size_t i, std::string& db, std::string& name) {
	if (!isName(t, i)) return npos;
	name = lower(t[i].text);
	db.clear();
	i++;
	if (isPunct(t, i, ".")) {
		if (!isName(t, i + 1)) return npos;
		db = name;
		name = lower(t[i + 1].text);
		i += 2;
		if (isPunct(t, i, ".")) return npos;
	}
	return i;
}

inline size_t recordName(Scan& s, size_t i) {
	std::string db, name;
	size_t next = tableName(s.t, i, db, name);
	if (next == npos) { s.fail(); return npos; }
	record(s, i, db, name);
	return next;
}

inline size_t skipAlias(Scan& s, size_t i, bool derived) {
	const auto& t = s.t;
	if (isWord(t, i, "AS")) {
		if (!(isName(t, i + 1) || isKind(t, i + 1, TokKind::Str))) { s.fail(); return npos; }
		i += 2;
	} else if (isKind(t, i, TokKind::QuotedIdent) || (isKind(t, i, TokKind::Word) && !notAlias(t[i].text))) {
		i++;
	}
	if (derived && isKind(t, i, TokKind::LParen)) { // (SELECT ...) AS d (a, b)
		size_t q = close(t, i);
		if (q == npos) { s.fail(); return npos; }
		i = q + 1;
	}
	return i;
}

// skipIndexHints: [,] {USE|IGNORE|FORCE} {INDEX|KEY} [FOR {JOIN|ORDER BY|GROUP BY}] (...), repeated.
inline size_t skipIndexHints(Scan& s, size_t i) {
	const auto& t = s.t;
	for (;;) {
		size_t j = isPunct(t, i, ",") ? i + 1 : i;
		if (!anyOf(t, j, {"USE", "IGNORE", "FORCE"}) || !anyOf(t, j + 1, {"INDEX", "KEY"})) return i;
		j += 2;
		if (isWord(t, j, "FOR")) {
			if (isWord(t, j + 1, "JOIN")) { s.joined[j + 1] = true; j += 2; }
			else if (anyOf(t, j + 1, {"ORDER", "GROUP"}) && isWord(t, j + 2, "BY")) j += 3;
			else { s.fail(); return npos; }
		}
		size_t q = isKind(t, j, TokKind::LParen) ? close(t, j) : npos;
		if (q == npos) { s.fail(); return npos; }
		i = q + 1;
	}
}

inline size_t tableRefs(Scan& s, size_t i);

// derivedAt: is the parenthesis at i a query (a derived table) rather than a join in parentheses?
inline bool derivedAt(const std::vector<Tok>& t, size_t i, size_t q) {
	if (anyOf(t, i + 1, queryStarts())) return true;
	if (!isKind(t, i + 1, TokKind::LParen)) return false;
	// ((SELECT ...) UNION (SELECT ...)): a set operation, ORDER BY or LIMIT directly inside.
	int d = 0;
	for (size_t j = i + 1; j < q; j++) {
		if (t[j].kind == TokKind::LParen) d++;
		else if (t[j].kind == TokKind::RParen) d--;
		else if (d == 0 && anyOf(t, j, {"UNION", "INTERSECT", "EXCEPT", "ORDER", "LIMIT"})) return true;
	}
	return false;
}

// tableRef reads one table reference at i and returns the index after it.
inline size_t tableRef(Scan& s, size_t i) {
	const auto& t = s.t;
	if (isWord(t, i, "LATERAL")) i++;
	if (isKind(t, i, TokKind::LParen)) {
		size_t q = close(t, i);
		if (q == npos) { s.fail(); return npos; }
		if (derivedAt(t, i, q)) return skipAlias(s, q + 1, true); // its own FROM is read where it stands
		size_t end = tableRefs(s, i + 1);
		if (!s.ok) return npos;
		if (end != q) { s.fail(); return npos; }
		return skipAlias(s, q + 1, false);
	}
	if (isWord(t, i, "JSON_TABLE") && isKind(t, i + 1, TokKind::LParen)) {
		size_t q = close(t, i + 1);
		if (q == npos) { s.fail(); return npos; }
		return skipAlias(s, q + 1, false);
	}
	if (isWord(t, i, "DUAL")) return i + 1;
	i = recordName(s, i);
	if (!s.ok) return npos;
	if (isWord(t, i, "PARTITION") && isKind(t, i + 1, TokKind::LParen)) {
		size_t q = close(t, i + 1);
		if (q == npos) { s.fail(); return npos; }
		i = q + 1;
	}
	i = skipAlias(s, i, false);
	if (!s.ok) return npos;
	return skipIndexHints(s, i);
}

// tableRefs reads a table list -- FROM's, UPDATE's, DELETE ... USING's, or one in parentheses --
// starting at i, and returns where it ends: a clause that follows the list, a closing parenthesis
// or the end. Anything else after a table reference is refused rather than guessed.
inline size_t tableRefs(Scan& s, size_t i) {
	const auto& t = s.t;
	for (;;) {
		i = tableRef(s, i);
		if (!s.ok) return npos;
		bool inOn = false; // inside an ON condition, which is read where it stands
		for (;;) {
			if (i >= t.size() || t[i].kind == TokKind::RParen) return i;
			if (isPunct(t, i, ",")) { i++; break; }
			// ON a.where = 1: a reserved word after a period (or @) is a name, not a clause.
			if (t[i].kind == TokKind::Word && !isPunct(t, i - 1, ".") && !isPunct(t, i - 1, "@")) {
				const std::string& w = t[i].text;
				if (w == "JOIN" || w == "STRAIGHT_JOIN") { s.joined[i] = true; i++; break; }
				if (joinWords().count(w)) { i++; continue; }
				if (w == "ON") {
					if (isWord(t, i + 1, "DUPLICATE")) return i; // INSERT ... SELECT ... ON DUPLICATE KEY UPDATE
					inOn = true;
					i++;
					continue;
				}
				if (w == "USING") {
					if (!isKind(t, i + 1, TokKind::LParen)) return i;
					size_t q = close(t, i + 1);
					if (q == npos) { s.fail(); return npos; }
					i = q + 1;
					inOn = false;
					continue;
				}
				if (listEnds().count(w)) return i;
			}
			if (!inOn) { s.fail(); return npos; }
			if (t[i].kind == TokKind::LParen) {
				size_t q = close(t, i);
				if (q == npos) { s.fail(); return npos; }
				i = q + 1;
				continue;
			}
			i++;
		}
	}
}

// cteAt: WITH [RECURSIVE] name [(columns)] AS ( -- not WITH ROLLUP and the like.
inline bool cteAt(const std::vector<Tok>& t, size_t i) {
	i++;
	if (isWord(t, i, "RECURSIVE")) i++;
	if (!isName(t, i)) return false;
	i++;
	if (isKind(t, i, TokKind::LParen)) {
		i = close(t, i);
		if (i == npos) return false;
		i++;
	}
	return isWord(t, i, "AS") && isKind(t, i + 1, TokKind::LParen);
}

// ctes puts a WITH clause's names in scope and returns the index after its last body.
inline size_t ctes(Scan& s, size_t i) {
	const auto& t = s.t;
	i++;
	bool recursive = isWord(t, i, "RECURSIVE");
	if (recursive) i++;
	for (;;) {
		if (!isName(t, i)) { s.fail(); return npos; }
		std::string name = lower(t[i].text);
		size_t at = i++;
		if (isKind(t, i, TokKind::LParen)) {
			i = close(t, i);
			if (i == npos) { s.fail(); return npos; }
			i++;
		}
		if (!isWord(t, i, "AS") || !isKind(t, i + 1, TokKind::LParen)) { s.fail(); return npos; }
		size_t q = close(t, i + 1);
		if (q == npos) { s.fail(); return npos; }
		s.ctes.push_back({name, s.depth, recursive ? at : q + 1});
		i = q + 1;
		if (!isPunct(t, i, ",")) return i;
		i++;
	}
}

// dmlHead reads the tables an INSERT, REPLACE, UPDATE or DELETE at i writes.
inline void dmlHead(Scan& s, size_t i, size_t& ignoreFrom) {
	const auto& t = s.t;
	const std::string& w = t[i].text;
	i++;
	if (w == "UPDATE") {
		while (anyOf(t, i, {"LOW_PRIORITY", "IGNORE"})) i++;
		tableRefs(s, i);
		return;
	}
	if (w == "INSERT" || w == "REPLACE") {
		while (anyOf(t, i, {"LOW_PRIORITY", "DELAYED", "HIGH_PRIORITY", "IGNORE"})) i++;
		if (isWord(t, i, "INTO")) i++;
		recordName(s, i);
		return;
	}
	// DELETE. DELETE FROM t ... and DELETE t1, t2 FROM <tables>: the FROM is read as anywhere else.
	// DELETE FROM t1, t2 USING <tables>: the tables are USING's.
	while (anyOf(t, i, {"LOW_PRIORITY", "QUICK", "IGNORE"})) i++;
	if (!isWord(t, i, "FROM")) return;
	int d = 0;
	for (size_t j = i + 1; j < t.size(); j++) {
		if (t[j].kind == TokKind::LParen) d++;
		else if (t[j].kind == TokKind::RParen) d--;
		else if (d == 0 && isWord(t, j, "USING") && !isKind(t, j + 1, TokKind::LParen)) {
			ignoreFrom = i;
			tableRefs(s, j + 1);
			return;
		}
	}
}

// walk reads a SELECT, WITH, TABLE, VALUES, INSERT, REPLACE, UPDATE, DELETE or SET statement.
inline void walk(Scan& s) {
	const auto& t = s.t;
	static const std::set<std::string> fromFunctions = {"EXTRACT", "TRIM", "SUBSTRING", "SUBSTR", "MID"};
	static const std::set<std::string> selectModifiers = {
		"SELECT", "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY", "SQL_SMALL_RESULT", "SQL_BIG_RESULT",
		"SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CACHE", "SQL_CALC_FOUND_ROWS",
	};
	std::vector<bool> noFrom; // per open parenthesis: a FROM directly inside is a function's (EXTRACT(YEAR FROM d))
	size_t head = 0, ignoreFrom = npos;
	for (size_t i = 0; i < t.size() && s.ok; i++) {
		if (t[i].kind == TokKind::LParen) {
			noFrom.push_back(i > 0 && t[i - 1].kind == TokKind::Word && fromFunctions.count(t[i - 1].text));
			s.depth++;
			continue;
		}
		if (t[i].kind == TokKind::RParen) {
			if (noFrom.empty()) { s.fail(); return; }
			noFrom.pop_back();
			s.depth--;
			while (!s.ctes.empty() && s.ctes.back().depth > s.depth) s.ctes.pop_back();
			continue;
		}
		if (t[i].kind != TokKind::Word) continue;
		if (isPunct(t, i - 1, ".") || isPunct(t, i - 1, "@")) continue; // o.from, @table: names
		const std::string& w = t[i].text;
		if (w == "WITH" && cteAt(t, i)) {
			size_t end = ctes(s, i);
			if (i == head) head = end; // WITH ... UPDATE / DELETE
			continue;
		}
		if (i == head && (w == "UPDATE" || w == "DELETE" || w == "INSERT" || w == "REPLACE")) {
			dmlHead(s, i, ignoreFrom);
			continue;
		}
		if (w == "FROM") {
			if (i == ignoreFrom || (!noFrom.empty() && noFrom.back())) continue;
			if (anyOf(t, i + 1, {"FIRST", "LAST"}) && anyOf(t, i + 2, {"OVER", "RESPECT", "IGNORE"})) continue; // NTH_VALUE
			tableRefs(s, i + 1);
			continue;
		}
		if (w == "TABLE") { recordName(s, i + 1); continue; }
		// A JOIN no table list read would be a table read past.
		if (w == "JOIN" && !s.joined[i]) s.fail();
		if (w == "STRAIGHT_JOIN" && !s.joined[i] && !(i > 0 && anyOf(t, i - 1, selectModifiers))) s.fail();
	}
	if (!noFrom.empty()) s.fail();
}

inline bool statement(const std::vector<Tok>& t, std::vector<Ref>& refs);

// show: SHOW COLUMNS / INDEX ... FROM t [FROM db] and SHOW CREATE TABLE / VIEW t name a table; the
// other SHOWs name none.
inline bool show(const std::vector<Tok>& t, size_t i, std::vector<Ref>& refs) {
	for (size_t j = i; j + 1 < t.size(); j++) {
		if (t[j].kind == TokKind::LParen && anyOf(t, j + 1, queryStarts())) return false; // SHOW ... WHERE x IN (SELECT ...)
	}
	while (anyOf(t, i, {"FULL", "EXTENDED"})) i++;
	std::string db, name;
	if (anyOf(t, i, {"COLUMNS", "FIELDS", "INDEX", "INDEXES", "KEYS"})) {
		if (!anyOf(t, i + 1, {"FROM", "IN"})) return false;
		i = tableName(t, i + 2, db, name);
		if (i == npos) return false;
		if (anyOf(t, i, {"FROM", "IN"})) {
			if (!isName(t, i + 1)) return false;
			db = lower(t[i + 1].text);
		}
		refs.push_back({db, name});
		return true;
	}
	if (isWord(t, i, "CREATE") && anyOf(t, i + 1, {"TABLE", "VIEW"})) {
		if (tableName(t, i + 2, db, name) == npos) return false;
		refs.push_back({db, name});
	}
	return true;
}

// describe: {DESCRIBE|DESC|EXPLAIN} t [column], or {...} [options] <statement>.
inline bool describe(const std::vector<Tok>& t, size_t i, std::vector<Ref>& refs) {
	for (;;) {
		if (anyOf(t, i, {"ANALYZE", "EXTENDED", "PARTITIONS"})) { i++; continue; }
		if (isWord(t, i, "FORMAT")) {
			i++;
			if (isPunct(t, i, "=")) i++;
			if (isName(t, i) || isKind(t, i, TokKind::Str)) i++;
			continue;
		}
		break;
	}
	if (isKind(t, i, TokKind::LParen) ||
		anyOf(t, i, {"SELECT", "WITH", "VALUES", "TABLE", "INSERT", "REPLACE", "UPDATE", "DELETE"})) {
		return statement(std::vector<Tok>(t.begin() + static_cast<long>(i), t.end()), refs);
	}
	if (isWord(t, i, "FOR")) return false; // EXPLAIN FOR CONNECTION: another session's statement
	std::string db, name;
	i = tableName(t, i, db, name);
	if (i == npos) return false;
	refs.push_back({db, name});
	if (isName(t, i) || isKind(t, i, TokKind::Str)) i++; // a column, or a pattern
	return i == t.size();
}

// statement adds the tables t names to refs; false when it cannot be read with confidence.
inline bool statement(const std::vector<Tok>& t, std::vector<Ref>& refs) {
	size_t first = 0;
	while (isKind(t, first, TokKind::LParen)) first++;
	if (t.empty()) return true;
	if (!isKind(t, first, TokKind::Word)) return false;
	const std::string& k = t[first].text;
	if (k == "SELECT" || k == "WITH" || k == "TABLE" || k == "VALUES" || k == "INSERT" || k == "REPLACE" ||
		k == "UPDATE" || k == "DELETE" || k == "SET") {
		Scan s(t, refs);
		walk(s);
		return s.ok;
	}
	if (k == "TRUNCATE") {
		size_t i = isWord(t, first + 1, "TABLE") ? first + 2 : first + 1;
		std::string db, name;
		i = tableName(t, i, db, name);
		if (i == npos) return false;
		refs.push_back({db, name});
		return i == t.size();
	}
	if (k == "DESCRIBE" || k == "DESC" || k == "EXPLAIN") return describe(t, first + 1, refs);
	if (k == "SHOW") return show(t, first + 1, refs);
	// Client housekeeping (authnull_query.h) names no table. It reads the statement without
	// punctuation, as the privilege check does.
	std::vector<Tok> words;
	for (const auto& x : t) {
		if (x.kind != TokKind::Punct) words.push_back(x);
	}
	std::set<std::string> need;
	return authnull_query_detail::classifyHousekeeping(words, first, AuthnullDialect::MySQL, need);
}

} // namespace authnull_tables_detail

// authnullTablesNamed: the tables every statement in sql names, as {db, table} in lower case (db
// empty when not written). ok is false when sql could not be read with confidence.
inline std::vector<std::pair<std::string, std::string>> authnullTablesNamed(const std::string& sql, bool& ok) {
	std::vector<std::pair<std::string, std::string>> refs;
	std::vector<std::vector<authnull_query_detail::Tok>> statements;
	ok = authnull_query_detail::lex(sql, AuthnullDialect::MySQL, statements, true);
	for (size_t i = 0; ok && i < statements.size(); i++) ok = authnull_tables_detail::statement(statements[i], refs);
	return refs;
}

// authnullTablesPermitted: may a session whose policy lists these tables, in database db, run sql?
// An empty list restricts nothing.
inline bool authnullTablesPermitted(const std::vector<std::string>& tables, const std::string& db, const std::string& sql) {
	using authnull_query_detail::lower;
	if (tables.empty()) return true;
	const std::string session = lower(db);
	std::set<std::string> allowed;
	for (const auto& entry : tables) {
		std::string e;
		for (char c : entry) {
			if (!std::isspace(static_cast<unsigned char>(c))) e += c;
		}
		e = lower(e);
		size_t dot = e.find('.');
		if (dot == std::string::npos) allowed.insert(e);
		else if (e.substr(0, dot) == session) allowed.insert(e.substr(dot + 1));
	}
	bool ok = false;
	auto refs = authnullTablesNamed(sql, ok);
	if (!ok) return false;
	for (const auto& r : refs) {
		const std::string& in = r.first.empty() ? session : r.first;
		if (in == "information_schema") continue;
		if (in == "mysql" || in == "performance_schema" || in == "sys") return false;
		if (in != session || !allowed.count(r.second)) return false;
	}
	return true;
}

#endif // AUTHNULL_TABLES_H
