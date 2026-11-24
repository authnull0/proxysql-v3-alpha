// Field masking for PostgreSQL and MySQL results: which columns a policy's masking covers, masking
// them, and refusing the queries that would read a masked value some other way.
//
// A database policy can name columns to mask per table (field_masking: {"orders": ["amount"]}).
// authn-service sends it with the login answer; the session keeps it with the query it is running
// (PgSQL_Session, MySQL_Session), and the result set masks the rows on their way to the client
// (PgSQL_Query_Result, MySQL_ResultSet): a text value becomes '*' of the same length, so the row
// keeps its size; NULL stays NULL; a PostgreSQL binary-format value is zeroed; in a MySQL
// binary-protocol row (prepared statements) a masked number, date, decimal or bit value becomes NULL,
// as a '*' cannot be written into it. The column metadata is read once per result set to decide the
// columns.
//
// Which columns (authnullMaskColumns), for a policy naming column c:
//   - a result column named c, whatever its table or expression (amount, amount::text, "AMOUNT");
//   - a name the query gives a value computed from c: a select-list alias (amount AS a, upper(amount)
//     a, a subquery's alias), a derived table's or CTE's column list (t(x), WITH w(x) AS ...), and on
//     PostgreSQL a whole-row reference to a table holding c (SELECT o FROM orders o; a derived
//     table's or CTE's name);
//   - MySQL: a column whose source column (org_name) is c, whatever it is called (amount 'a');
//   - an expression (no source table: amount * 1, sum(amount), concat(...), row_to_json(o)) when the
//     query uses c or one of those names anywhere -- conservative: such a column may carry c's value
//     under any name. On MySQL a "..." string that spells c counts too: with ANSI_QUOTES, "amount" is
//     the column.
// A table column whose name the policy does not mask is left alone. Names compare in any case; the
// policy is not split by table, so a masked name masks that name from any table (it never shows less
// than asked).
//
// Which queries are refused (authnullMaskRefused). Masking hides a value on its way out, but a query
// can test the value without returning it: SELECT id FROM orders WHERE amount = 37.5 answers by which
// rows come back. So in a statement that reads a table with masked columns, a masked value (c, or one
// of the names above) may appear only in a select list whose rows go to the client -- directly, or
// through a derived table or CTE that is held to the same rule -- where it is masked. Anywhere else the
// statement is refused like a query the policy does not permit:
//   - WHERE, ON, USING, HAVING, GROUP BY, ORDER BY (also by position), PARTITION BY and the rest of a
//     window, LIMIT, a subquery anywhere but a select list or FROM;
//   - DISTINCT, UNION (not ALL), INTERSECT, EXCEPT: they compare the values;
//   - statements that do not send their select list to the client: INSERT ... SELECT, UPDATE ... SET
//     x = c, DELETE ... WHERE c, CREATE ... AS SELECT, SELECT ... INTO, MySQL @v := c, EXPLAIN. In
//     these, SELECT * and TABLE of a masked table count too: they copy c without naming it.
// Writing c is not reading it: INSERT INTO t (c) VALUES (...), UPDATE t SET c = 'x' (a WHERE not on c),
// ON DUPLICATE KEY UPDATE c = VALUES(c), ON CONFLICT ... SET c = EXCLUDED.c, and RETURNING c (masked).
//
// LIMITS. A view or function that returns c under another name is not followed: name the view's
// columns in the policy too (the view then counts as a table with masked columns). Nor is a value
// carried between statements by PREPARE/EXECUTE by name. Inside a select list c can still drive a
// computation whose failure or delay shows (CASE WHEN c = 'x' THEN 1/0 END): the policy decision was
// to allow expressions there, as their result is masked. This reads result names and query text; the
// database's own column privileges are the stronger control where columns must never leave the server.
#ifndef AUTHNULL_MASKING_H
#define AUTHNULL_MASKING_H

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "authnull_query.h"

struct AuthnullResultColumn {
	std::string name;  // as the row description gives it
	bool fromTable;    // the row description names a source table (OID != 0)
	bool binary;       // binary format (1) rather than text (0)
	std::string orgName = {}; // MySQL: the source column (org_name) when there is one
};

// What a query does with the masked values: authnullMaskUse.
struct AuthnullMaskUse {
	bool readable = true;    // false when the query could not be read to the end
	bool mentioned = false;  // a masked value is used somewhere in the query
	bool refuse = false;     // a statement reading a masked table uses one where it is not masked on the way out
	std::set<std::string> names; // the masked names and the names the query gives masked values, lower case
};

namespace authnull_masking_detail {

using authnull_query_detail::Tok;
using authnull_query_detail::TokKind;

constexpr size_t kNone = static_cast<size_t>(-1);

inline std::string lowerCopy(const std::string& s) {
	std::string out = s;
	for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return out;
}

inline bool isName(const Tok& t) {
	return t.kind == TokKind::Word || t.kind == TokKind::QuotedIdent;
}

inline bool wordAt(const std::vector<Tok>& t, size_t i, const char* w) {
	return i < t.size() && t[i].kind == TokKind::Word && t[i].text == w;
}

inline bool punctAt(const std::vector<Tok>& t, size_t i, char c) {
	return i < t.size() && t[i].kind == TokKind::Punct && t[i].text[0] == c;
}

// Keywords that end or join expressions: not an alias, and a name after one is not an alias either.
inline bool reserved(const Tok& x) {
	static const std::set<std::string> s = {
		"SELECT", "FROM", "WHERE", "GROUP", "ORDER", "BY", "HAVING", "LIMIT", "OFFSET", "FETCH", "UNION",
		"INTERSECT", "EXCEPT", "MINUS", "ALL", "DISTINCT", "DISTINCTROW", "AND", "OR", "NOT", "XOR", "IS",
		"NULL", "TRUE", "FALSE", "UNKNOWN", "IN", "LIKE", "ILIKE", "SIMILAR", "BETWEEN", "CASE", "WHEN",
		"THEN", "ELSE", "END", "AS", "ON", "JOIN", "STRAIGHT_JOIN", "USING", "INNER", "LEFT", "RIGHT", "FULL",
		"OUTER", "CROSS", "NATURAL", "LATERAL", "INTO", "FOR", "WINDOW", "OVER", "PARTITION", "ASC", "DESC",
		"NULLS", "COLLATE", "ESCAPE", "DIV", "MOD", "REGEXP", "RLIKE", "SOUNDS", "BINARY", "INTERVAL",
		"RETURNING", "VALUES", "SET", "WITH", "EXISTS", "ANY", "SOME", "ARRAY", "FILTER", "WITHIN", "QUALIFY",
		"ONLY", "TABLESAMPLE", "MATERIALIZED", "TABLE",
	};
	return x.kind == TokKind::Word && s.count(x.text);
}

inline bool isNumber(const Tok& x) {
	return x.kind == TokKind::Word && !x.text.empty() && std::isdigit(static_cast<unsigned char>(x.text[0]));
}

// An identifier: quoted, or a word that is neither a keyword nor a number.
inline bool identTok(const Tok& x) {
	return x.kind == TokKind::QuotedIdent || (x.kind == TokKind::Word && !reserved(x) && !isNumber(x));
}

// Where a token sits, for what a masked value there means.
enum class Clause {
	Start,     // nothing read yet, or after UNION / INTERSECT / EXCEPT
	Select,    // a select list, or RETURNING: a masked value here is masked on the way out
	From,      // FROM / JOIN table references, UPDATE's tables
	With,      // CTE names
	Names,     // a column list naming a derived table's, CTE's or table alias's columns
	Skip,      // write targets: INSERT's table and columns, INTO targets, VALUES(c)
	SetTarget, // SET x = ...: before the '='
	SetValue,  // ... after it
	Other,     // the rest, which reads values: WHERE, ON, ORDER BY, VALUES, a function in FROM, ...
};

// One parenthesis level of a statement.
struct Frame {
	Clause clause = Clause::Start;
	bool parentOk = true;  // a query here would sit where its select list reaches only the client
	bool stmtOk = true;    // ... and this level's statement is a query (not INSERT, EXPLAIN, ...)
	bool outOk = true;     // the select list being read reaches only the client
	bool distinct = false; // ... and is DISTINCT
	bool call = false;     // opened by a function call
	bool query = false;    // has a select list (or RETURNING) of its own
	bool started = false;  // a token has been read at this level
	bool byList = false;   // in ORDER BY / GROUP BY: a bare number is a select-list position
	bool derived = false;  // a derived table: FROM ( ... )
	bool anyUse = false;   // a masked value is used at this level or below
	bool itemUse = false;  // ... in the select-list item being read
	size_t last = kNone, prev = kNone; // the last two tokens at this level (a group counts as its ')')
	size_t derivedClose = kNone;       // the ')' that closed a derived table here
	size_t itemStart = 0, itemNo = 0;
	size_t starAt = kNone;   // the first select-list position that is a SELECT * (its columns' positions are unknown)
	std::vector<bool> items; // per select-list position: uses a masked value
};

// One reading of the query (authnullMaskUse reads it until no new name turns up).
struct Pass {
	bool mentioned = false;
	bool refuse = false;
	std::set<std::string> grow; // names found to carry masked values
};

// scanStatement reads one statement: where it uses the names that carry masked values (names), and
// which other names it gives them. tables: the policy's tables with masked columns.
inline void scanStatement(const std::vector<Tok>& t, AuthnullDialect d, const std::set<std::string>& names,
	const std::set<std::string>& tables, Pass& pass) {
	const bool pg = d == AuthnullDialect::Postgres;
	bool maskedTable = false, involved = false;
	for (const auto& x : t) {
		if (!isName(x)) continue;
		const std::string n = lowerCopy(x.text);
		if (tables.count(n)) maskedTable = true;
		if (names.count(n)) involved = true;
	}
	involved = involved || maskedTable;
	bool allValues = false; // the statement uses every value it reads beyond the select list (UNION, INTO, :=)
	bool anyUse = false, refuse = false;
	std::vector<Frame> st(1);

	// endItem: the select-list item being read ends; an alias it gives a masked value carries it too.
	auto endItem = [&](Frame& f, size_t next) {
		if (!f.query || f.clause != Clause::Select) return;
		if (f.itemUse && f.last != kNone && f.last >= f.itemStart && f.prev != kNone && f.prev >= f.itemStart) {
			const Tok& a = t[f.last];
			const Tok& b = t[f.prev];
			const bool aliasLike = identTok(a) || (!pg && a.kind == TokKind::Str); // MySQL: item 'a'
			const bool afterValue = identTok(b) || isNumber(b) || b.kind == TokKind::RParen || b.kind == TokKind::Str ||
				wordAt(t, f.prev, "AS") || wordAt(t, f.prev, "END") || wordAt(t, f.prev, "NULL") ||
				wordAt(t, f.prev, "TRUE") || wordAt(t, f.prev, "FALSE");
			if (aliasLike && afterValue) pass.grow.insert(lowerCopy(a.text));
		}
		if (f.items.size() <= f.itemNo) f.items.resize(f.itemNo + 1, false);
		if (f.itemUse) f.items[f.itemNo] = true;
		f.itemNo++;
		f.itemUse = false;
		f.itemStart = next;
	};
	auto setClause = [&](Frame& f, Clause c, size_t i) {
		endItem(f, i + 1);
		f.clause = c;
		f.byList = false;
	};
	auto selectStarts = [&](Frame& f, size_t i, bool outOk) {
		setClause(f, Clause::Select, i);
		f.query = true;
		f.outOk = outOk;
		f.distinct = false;
		static const std::set<std::string> modifiers = {
			"ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY", "STRAIGHT_JOIN", "SQL_SMALL_RESULT",
			"SQL_BIG_RESULT", "SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CACHE", "SQL_CALC_FOUND_ROWS",
		};
		size_t j = i + 1;
		while (j < t.size() && t[j].kind == TokKind::Word && modifiers.count(t[j].text)) {
			// DISTINCT ON (a): compares a only (the ON list reads as Other).
			if ((t[j].text == "DISTINCT" || t[j].text == "DISTINCTROW") && !wordAt(t, j + 1, "ON")) f.distinct = true;
			j++;
		}
		f.itemStart = j;
		f.itemNo = 0;
		f.itemUse = false;
	};
	// use: a masked value is used here. counts: it makes expression columns masked (a whole SELECT *
	// item does not: its columns are the table's own and masked by name).
	auto use = [&](Frame& f, bool counts) {
		if (counts) pass.mentioned = true;
		anyUse = true;
		f.anyUse = true;
		if (f.clause == Clause::Select) f.itemUse = true;
		if (!(f.clause == Clause::Select && f.outOk && !f.distinct)) refuse = true;
	};
	auto closeFrame = [&](size_t i) {
		Frame c = st.back();
		st.pop_back();
		endItem(c, i);
		Frame& p = st.back();
		if (c.anyUse) {
			p.anyUse = true;
			if (p.clause == Clause::Select) p.itemUse = true;
		}
		if (c.derived) p.derivedClose = i;
		p.started = true;
		if (i < t.size()) {
			p.prev = p.last;
			p.last = i;
		}
	};
	auto nameAt = [&](Frame& f, size_t i) {
		const Tok& k = t[i];
		const std::string n = lowerCopy(k.text);
		switch (f.clause) {
		case Clause::From:
			// PostgreSQL: a whole-row reference reads every column, so the masked table's name and
			// alias, and a derived table's alias, carry its masked values.
			if (pg && k.kind != TokKind::Str) {
				if (tables.count(n) && !punctAt(t, i + 1, '.')) pass.grow.insert(n);
				const size_t before = wordAt(t, f.last, "AS") ? f.prev : f.last;
				if (identTok(k) && before != kNone) {
					if (isName(t[before]) && tables.count(lowerCopy(t[before].text))) pass.grow.insert(n); // orders o
					if (before == f.derivedClose && involved) pass.grow.insert(n);                       // (SELECT ...) s
				}
			}
			return;
		case Clause::With:
			if (pg && involved && identTok(k) && (wordAt(t, i + 1, "AS") || (i + 1 < t.size() && t[i + 1].kind == TokKind::LParen))) {
				pass.grow.insert(n); // a CTE's name: a whole-row reference to it
			}
			return;
		case Clause::Names:
			if (involved && k.kind != TokKind::Str) pass.grow.insert(n); // t(x): x may be any of its columns
			return;
		case Clause::Skip:
		case Clause::SetTarget:
			return;
		default:
			break;
		}
		if (!names.count(n)) return;
		// A qualifier (o.item), a function, an alias being given, a type (::orders) are not values.
		if (punctAt(t, i + 1, '.') || authnull_query_detail::calledAt(t, i) || wordAt(t, f.last, "AS")) return;
		if (pg && punctAt(t, i - 1, ':')) return;
		if (f.clause == Clause::SetValue && punctAt(t, i - 1, '.') && wordAt(t, i - 2, "EXCLUDED")) return; // the row being inserted
		use(f, true);
	};

	for (size_t i = 0; i < t.size(); i++) {
		const Tok& k = t[i];
		if (k.kind == TokKind::LParen) {
			const Frame& p = st.back();
			Frame c;
			c.call = p.last != kNone && identTok(t[p.last]);
			c.parentOk = p.outOk && ((p.clause == Clause::Select && !p.distinct) || p.clause == Clause::From ||
				p.clause == Clause::With || p.clause == Clause::Start);
			c.stmtOk = c.parentOk;
			c.clause = p.clause;
			c.outOk = p.outOk;
			c.distinct = p.distinct;
			c.itemStart = i + 1;
			switch (p.clause) {
			case Clause::From:
				if (!c.call) { // FROM (SELECT ...) or a parenthesised join
					c.derived = true;
					c.outOk = c.parentOk;
				} else if (p.prev != kNone && (identTok(t[p.prev]) || t[p.prev].kind == TokKind::RParen || wordAt(t, p.prev, "AS"))) {
					c.clause = Clause::Names; // orders o(a, b), (SELECT ...) t(x)
				} else {
					c.clause = Clause::Other; // a function: its arguments are values
				}
				break;
			case Clause::With:
				c.clause = c.call ? Clause::Names : Clause::Start; // w(a, b) or AS ( ... )
				c.outOk = c.parentOk;
				break;
			case Clause::Start:
				c.outOk = c.parentOk;
				break;
			case Clause::Skip:
			case Clause::SetTarget:
				c.clause = Clause::Skip;
				break;
			case Clause::SetValue:
				c.clause = wordAt(t, p.last, "VALUES") ? Clause::Skip : Clause::Other; // VALUES(c): the row being inserted
				break;
			case Clause::Select:
				if (wordAt(t, p.last, "ON") && wordAt(t, p.prev, "DISTINCT")) c.clause = Clause::Other;
				break;
			default:
				break;
			}
			st.push_back(c);
			continue;
		}
		if (k.kind == TokKind::RParen && st.size() > 1) {
			closeFrame(i);
			continue;
		}
		Frame& f = st.back();
		const bool first = !f.started && (st.size() == 1 || !f.call);
		f.started = true;
		const std::string& w = k.text;
		bool keyword = k.kind == TokKind::Word;
		if (keyword) {
			const bool called = authnull_query_detail::calledAt(t, i);
			if (w == "SELECT") {
				selectStarts(f, i, f.stmtOk);
			} else if (w == "WITH" && (first || wordAt(t, i + 1, "RECURSIVE") ||
				(i + 2 < t.size() && identTok(t[i + 1]) && !wordAt(t, i + 1, "ORDINALITY") &&
				 (wordAt(t, i + 2, "AS") || t[i + 2].kind == TokKind::LParen)))) {
				setClause(f, Clause::With, i);
			} else if (w == "TABLE" && (first || f.clause == Clause::Start ||
				(f.clause == Clause::Skip && f.last != kNone && (identTok(t[f.last]) || t[f.last].kind == TokKind::RParen)))) {
				// TABLE orders: SELECT * FROM orders (also INSERT INTO t TABLE orders)
				selectStarts(f, i, f.stmtOk);
				if (i + 1 < t.size() && isName(t[i + 1]) && tables.count(lowerCopy(t[i + 1].text))) use(f, false);
			} else if (w == "UPDATE" && (wordAt(t, f.last, "KEY") || wordAt(t, f.last, "DO") || wordAt(t, f.last, "THEN"))) {
				setClause(f, Clause::SetTarget, i); // ON DUPLICATE KEY UPDATE, ON CONFLICT DO UPDATE, MERGE
			} else if (!called && !wordAt(t, f.last, "FOR") &&
				(w == "INSERT" || w == "REPLACE" || w == "UPDATE" || w == "DELETE" || w == "MERGE")) {
				f.stmtOk = f.outOk = false; // a write: what it selects goes into a table
				setClause(f, w == "UPDATE" ? Clause::From : (w == "DELETE" || w == "MERGE") ? Clause::Other : Clause::Skip, i);
			} else if (first && st.size() == 1 && w != "VALUES") {
				f.stmtOk = f.outOk = false; // EXPLAIN, SHOW, CREATE ... AS, SET, DO, CALL, ...
				setClause(f, Clause::Other, i);
			} else if (w == "VALUES" && f.clause != Clause::SetValue) { // (in SET, VALUES(c) is MySQL's inserted value)
				setClause(f, Clause::Other, i);
			} else if (w == "FROM" && (f.query || !f.call) && !wordAt(t, f.last, "DISTINCT")) {
				setClause(f, Clause::From, i);
			} else if ((w == "JOIN" || w == "STRAIGHT_JOIN") && (f.query || !f.call)) {
				setClause(f, Clause::From, i);
			} else if (w == "WHERE" || w == "HAVING" || w == "WINDOW" || w == "QUALIFY") {
				setClause(f, Clause::Other, i);
			} else if (w == "NATURAL") {
				refuse = true; // NATURAL JOIN compares every column the tables share, masked ones too
			} else if ((w == "ON" || w == "USING" || w == "LIMIT" || w == "OFFSET" || w == "FETCH") &&
				(f.query || !f.call) && !wordAt(t, f.last, "DISTINCT")) {
				setClause(f, Clause::Other, i);
			} else if ((w == "GROUP" || w == "ORDER" || w == "PARTITION") && wordAt(t, i + 1, "BY")) {
				setClause(f, Clause::Other, i);
				f.byList = true;
			} else if (w == "UNION" || w == "INTERSECT" || w == "EXCEPT" || w == "MINUS") {
				if (!(w == "UNION" && wordAt(t, i + 1, "ALL"))) allValues = true;
				setClause(f, Clause::Start, i);
				f.outOk = f.stmtOk;
			} else if (w == "INTO") {
				if (f.clause != Clause::Skip && f.query) allValues = true; // SELECT ... INTO: not to the client
				setClause(f, Clause::Skip, i);
			} else if (w == "SET" && !f.call) {
				setClause(f, Clause::SetTarget, i);
			} else if (w == "RETURNING") {
				selectStarts(f, i, f.parentOk);
			} else {
				keyword = false;
			}
		}
		if (!keyword) {
			if (k.kind == TokKind::Punct) {
				const char c = w[0];
				if (c == ',' && f.clause == Clause::Select) {
					endItem(f, i + 1);
				} else if (c == ',' && f.clause == Clause::SetValue) {
					f.clause = Clause::SetTarget;
				} else if (c == '=' && f.clause == Clause::SetTarget) {
					f.clause = Clause::SetValue;
				} else if (c == '=' && !pg && punctAt(t, i - 1, ':')) {
					allValues = true; // @v := c keeps the value for a later statement
				} else if (c == '*' && maskedTable) {
					// SELECT *, o.*: the table's columns, masked by name -- but copied unmasked where
					// the select list does not go to the client. PostgreSQL row_to_json(o.*): a whole row.
					const bool qualified = punctAt(t, i - 1, '.');
					const bool wholeItem = f.query && f.clause == Clause::Select &&
						(i == f.itemStart || (qualified && (i - f.itemStart == 2 || i - f.itemStart == 4)));
					if (wholeItem && f.starAt == kNone) f.starAt = f.itemNo;
					if (qualified || wholeItem) use(f, !wholeItem);
				}
			} else if (identTok(k) || k.kind == TokKind::QuotedIdent || (!pg && k.kind == TokKind::Str && k.dquoted)) {
				nameAt(f, i);
			} else if (isNumber(k) && f.byList && f.query && (wordAt(t, f.last, "BY") || punctAt(t, f.last, ','))) {
				// ORDER BY 2: the second select-list item.
				bool digits = w.size() < 7;
				for (char ch : w) digits = digits && std::isdigit(static_cast<unsigned char>(ch));
				if (digits) {
					const size_t pos = static_cast<size_t>(std::stoul(w));
					if (pos >= 1 && ((pos <= f.items.size() && f.items[pos - 1]) || (f.starAt != kNone && pos - 1 >= f.starAt))) refuse = true;
				}
			}
		}
		f.prev = f.last;
		f.last = i;
	}
	while (st.size() > 1) closeFrame(t.size());
	endItem(st.back(), t.size());
	if (allValues && anyUse) refuse = true;
	if (maskedTable && refuse) pass.refuse = true;
}

} // namespace authnull_masking_detail

// authnullMaskedNames: every column the policy masks, lower case.
inline std::set<std::string> authnullMaskedNames(const std::map<std::string, std::vector<std::string>>& policy) {
	std::set<std::string> out;
	for (const auto& t : policy) {
		for (const auto& c : t.second) {
			if (!c.empty()) out.insert(authnull_masking_detail::lowerCopy(c));
		}
	}
	return out;
}

// authnullMaskUse reads sql for what it does with the policy's masked values (the header's rules).
// d is how the query text reads: Postgres, or MySQL (backticks, '#' comments, "..." strings).
inline AuthnullMaskUse authnullMaskUse(const std::map<std::string, std::vector<std::string>>& policy,
	const std::string& sql, AuthnullDialect d) {
	using namespace authnull_masking_detail;
	AuthnullMaskUse out;
	out.names = authnullMaskedNames(policy);
	if (out.names.empty()) return out;
	// The tables with masked columns, by their last name part (shop.orders, "orders").
	std::set<std::string> tables;
	for (const auto& t : policy) {
		bool masks = false;
		for (const auto& c : t.second) masks = masks || !c.empty();
		std::string n = lowerCopy(t.first);
		const size_t dot = n.find_last_of('.');
		if (dot != std::string::npos) n = n.substr(dot + 1);
		std::string bare;
		for (char c : n) if (c != '"' && c != '`') bare += c;
		if (masks && !bare.empty()) tables.insert(bare);
	}
	// Punctuation is kept: "amount, status" is not an alias.
	std::vector<std::vector<Tok>> statements;
	if (!authnull_query_detail::lex(sql, d, statements, true)) {
		out.readable = false;
		return out;
	}
	// A name given to a masked value can be used before it is given (SELECT z FROM (SELECT item z ...)):
	// read again until no new one turns up. Each reading that goes on adds a name from the query.
	for (;;) {
		Pass pass;
		for (const auto& s : statements) scanStatement(s, d, out.names, tables, pass);
		out.mentioned = pass.mentioned;
		out.refuse = pass.refuse;
		const size_t before = out.names.size();
		out.names.insert(pass.grow.begin(), pass.grow.end());
		if (out.names.size() == before) break;
	}
	return out;
}

// authnullMaskRefused: whether a session under this policy must be refused sql, as it would read a
// masked value without it being masked (the header's rules). A query that cannot be read is refused.
inline bool authnullMaskRefused(const std::map<std::string, std::vector<std::string>>& policy,
	const std::string& sql, AuthnullDialect d) {
	const AuthnullMaskUse use = authnullMaskUse(policy, sql, d);
	if (use.names.empty()) return false;
	return !use.readable || use.refuse;
}

// authnullMaskColumns: for each result column, whether to mask it (the header's rules).
inline std::vector<bool> authnullMaskColumns(const std::map<std::string, std::vector<std::string>>& policy,
	const std::vector<AuthnullResultColumn>& cols, const std::string& sql, AuthnullDialect d = AuthnullDialect::Postgres) {
	using authnull_masking_detail::lowerCopy;
	std::vector<bool> out(cols.size(), false);
	const AuthnullMaskUse use = authnullMaskUse(policy, sql, d);
	if (use.names.empty()) return out;
	// A query that cannot be read to the end mentions everything: expressions are then masked.
	const bool mentioned = !use.readable || use.mentioned;
	const std::set<std::string> masked = authnullMaskedNames(policy);
	for (size_t i = 0; i < cols.size(); i++) {
		if (use.names.count(lowerCopy(cols[i].name)) || masked.count(lowerCopy(cols[i].orgName))) out[i] = true;
		else if (!cols[i].fromTable && mentioned) out[i] = true;
	}
	return out;
}

// authnullMaskedValue: the masked form of one value of length len.
inline std::string authnullMaskedValue(const char* /*value*/, size_t len, bool binary) {
	return std::string(len, binary ? '\0' : '*');
}

// authnullMaskDataRow masks a PostgreSQL DataRow message ('D', int32 length, int16 count, then each
// column's int32 length -- -1 for NULL -- and bytes) in place: the masked columns' values, keeping
// every length. binary marks binary-format columns (missing = text). Returns false, changing
// nothing, when buf is not a well-formed DataRow of len bytes.
inline bool authnullMaskDataRow(uint8_t* buf, size_t len, const std::vector<bool>& mask, const std::vector<bool>& binary) {
	auto rd32 = [&](size_t at) -> int64_t {
		return (static_cast<int64_t>(buf[at]) << 24) | (static_cast<int64_t>(buf[at + 1]) << 16) |
			(static_cast<int64_t>(buf[at + 2]) << 8) | static_cast<int64_t>(buf[at + 3]);
	};
	if (len < 7 || buf[0] != 'D') return false;
	if (rd32(1) + 1 != static_cast<int64_t>(len)) return false;
	const size_t n = (static_cast<size_t>(buf[5]) << 8) | buf[6];

	// Check the whole row first, so a malformed one is left exactly as it came.
	std::vector<std::pair<size_t, size_t>> values; // offset, length; length 0 for NULL or empty
	size_t at = 7;
	for (size_t c = 0; c < n; c++) {
		if (at + 4 > len) return false;
		int64_t l = rd32(at);
		at += 4;
		if (l == 0xffffffffLL) { values.push_back({at, 0}); continue; } // NULL
		if (at + static_cast<size_t>(l) > len) return false;
		values.push_back({at, static_cast<size_t>(l)});
		at += static_cast<size_t>(l);
	}
	if (at != len) return false;

	for (size_t c = 0; c < values.size() && c < mask.size(); c++) {
		if (!mask[c] || values[c].second == 0) continue;
		const bool bin = c < binary.size() && binary[c];
		std::memset(buf + values[c].first, bin ? 0 : '*', values[c].second);
	}
	return true;
}

// authnullMaskBinaryRow masks a MySQL binary-protocol row (COM_STMT_EXECUTE: 0x00, a NULL bitmap
// offset by 2 bits, then the non-NULL values) in place. types are the columns' MySQL types
// (MYSQL_FIELD.type). A masked string, blob, enum, set or JSON value becomes '*' of its length; any
// other masked value -- integer, float, decimal, date, time, bit, geometry -- becomes NULL, as a '*'
// cannot be written into it. Returns the row's new length, never more than len. A row that cannot be
// read comes back with every column NULL rather than unmasked.
inline size_t authnullMaskBinaryRow(uint8_t* row, size_t len, const std::vector<bool>& mask, const std::vector<int>& types) {
	const size_t n = types.size();
	bool any = false;
	for (size_t c = 0; c < n && c < mask.size(); c++) any = any || mask[c];
	if (!any) return len;
	const size_t bitmap = (n + 7 + 2) / 8;
	if (len < 1 + bitmap) {
		std::memset(row, 0, len);
		return len;
	}
	auto isNull = [&](size_t c) { return ((row[1 + (c + 2) / 8] >> ((c + 2) % 8)) & 1) != 0; };
	auto setNull = [&](size_t c) { row[1 + (c + 2) / 8] |= static_cast<uint8_t>(1u << ((c + 2) % 8)); };
	// MySQL field_types.h: fixed-size values; everything else (strings, blobs, decimals, dates, times,
	// bits, JSON, geometry) is written with a length first.
	auto fixedSize = [](int type) -> int {
		switch (type) {
		case 6: return 0;            // NULL
		case 1: return 1;            // TINY
		case 2: case 13: return 2;   // SHORT, YEAR
		case 3: case 9: case 4: return 4; // LONG, INT24, FLOAT
		case 8: case 5: return 8;    // LONGLONG, DOUBLE
		default: return -1;
		}
	};
	auto isText = [](int type) {
		return type == 15 || (type >= 247 && type <= 254) || type == 245; // VARCHAR, ENUM..STRING, JSON
	};

	// Read the whole row first: where each value starts, where its bytes start, where it ends.
	struct Value { size_t start, body, end; };
	std::vector<Value> v(n, Value{0, 0, 0});
	bool ok = row[0] == 0;
	size_t at = 1 + bitmap;
	for (size_t c = 0; ok && c < n; c++) {
		if (isNull(c)) continue;
		size_t body = at, size = 0;
		const int fixed = fixedSize(types[c]);
		if (fixed >= 0) {
			size = static_cast<size_t>(fixed);
		} else {
			if (at >= len) { ok = false; break; }
			const uint8_t b = row[at];
			const size_t bytes = b < 0xfb ? 0 : b == 0xfc ? 2 : b == 0xfd ? 3 : b == 0xfe ? 8 : 9;
			if (bytes == 9 || len - at - 1 < bytes) { ok = false; break; }
			if (bytes == 0) size = b;
			for (size_t j = 0; j < bytes; j++) size |= static_cast<size_t>(row[at + 1 + j]) << (8 * j);
			body = at + 1 + bytes;
		}
		if (body > len || size > len - body) { ok = false; break; }
		v[c] = Value{at, body, body + size};
		at = body + size;
	}
	if (!ok || at != len) {
		row[0] = 0;
		std::memset(row + 1, 0, bitmap);
		for (size_t c = 0; c < n; c++) setNull(c);
		return 1 + bitmap;
	}

	// The row only shrinks: compact it in place.
	size_t out = 1 + bitmap;
	for (size_t c = 0; c < n; c++) {
		if (isNull(c)) continue;
		const bool m = c < mask.size() && mask[c];
		if (m && !isText(types[c])) {
			setNull(c);
			continue;
		}
		const size_t size = v[c].end - v[c].start;
		std::memmove(row + out, row + v[c].start, size);
		if (m) std::memset(row + out + (v[c].body - v[c].start), '*', v[c].end - v[c].body);
		out += size;
	}
	return out;
}

#endif // AUTHNULL_MASKING_H
