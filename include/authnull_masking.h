// Field masking for PostgreSQL results: which columns a policy's masking covers, and masking them.
//
// A database policy can name columns to mask per table (field_masking: {"orders": ["amount"]}).
// authn-service sends it with the login answer; the session keeps it with the query it is running
// (PgSQL_Session), and PgSQL_Query_Result masks the rows on their way to the client: a text value
// becomes '*' of the same length, so the row keeps its size; NULL stays NULL; a binary-format value
// is zeroed. The row description is read once per result set to decide the columns.
//
// Which columns (authnullMaskColumns), for a policy naming column c:
//   - a result column named c, whatever its table or expression (amount, amount::text, "AMOUNT");
//   - an alias of c in the query text (amount AS a, o.amount a, a subquery's alias);
//   - an expression (no source table: amount * 1, sum(amount), concat(...)) when the query mentions
//     c anywhere -- conservative: such a column may carry c's value under any name.
// A table column whose name the policy does not mask is left alone, even when c appears elsewhere in
// the query (WHERE amount > 10). Names compare in any case; the policy is not split by table, so a
// masked name masks that name from any table (it never shows less than asked).
//
// LIMITS. A view or function that returns c under another name is not followed: name the view's
// columns in the policy too. This reads result names and query text; the database's own column
// privileges are the stronger control where columns must never leave the server.
#ifndef AUTHNULL_MASKING_H
#define AUTHNULL_MASKING_H

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
};

namespace authnull_masking_detail {

inline std::string lowerCopy(const std::string& s) {
	std::string out = s;
	for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return out;
}

inline bool isName(const authnull_query_detail::Tok& t) {
	using authnull_query_detail::TokKind;
	return t.kind == TokKind::Word || t.kind == TokKind::QuotedIdent;
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

// authnullMaskColumns: for each result column, whether to mask it (the header's rules).
inline std::vector<bool> authnullMaskColumns(const std::map<std::string, std::vector<std::string>>& policy,
	const std::vector<AuthnullResultColumn>& cols, const std::string& sql) {
	using namespace authnull_masking_detail;
	std::vector<bool> out(cols.size(), false);
	const std::set<std::string> masked = authnullMaskedNames(policy);
	if (masked.empty()) return out;

	// The query's mentions of masked names, and the aliases given to them. A query that cannot be
	// read to the end mentions everything: expressions are then masked.
	std::set<std::string> aliases;
	bool mentioned = false;
	std::vector<std::vector<authnull_query_detail::Tok>> statements;
	if (!authnull_query_detail::lex(sql, AuthnullDialect::Postgres, statements)) {
		mentioned = true;
	} else {
		for (const auto& t : statements) {
			for (size_t i = 0; i < t.size(); i++) {
				if (!isName(t[i]) || !masked.count(lowerCopy(t[i].text))) continue;
				mentioned = true;
				size_t j = i + 1;
				if (j < t.size() && t[j].kind == authnull_query_detail::TokKind::Word && t[j].text == "AS") j++;
				if (j < t.size() && isName(t[j])) {
					const std::string next = lowerCopy(t[j].text);
					// "amount FROM", "amount, ..." are not aliases: keywords that follow a column.
					static const std::set<std::string> notAlias = {
						"from", "where", "group", "order", "having", "limit", "offset", "union", "intersect",
						"except", "and", "or", "not", "is", "in", "like", "ilike", "between", "asc", "desc",
						"nulls", "then", "else", "end", "when", "on", "join", "left", "right", "inner", "full",
						"cross", "into", "returning", "for", "window", "fetch", "using", "collate",
					};
					if (!notAlias.count(next)) aliases.insert(next);
				}
			}
		}
	}

	for (size_t i = 0; i < cols.size(); i++) {
		const std::string name = lowerCopy(cols[i].name);
		if (masked.count(name) || aliases.count(name)) out[i] = true;
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

#endif // AUTHNULL_MASKING_H
