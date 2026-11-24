// Standalone test for include/authnull_masking.h: which result columns a policy's field masking
// covers, and masking a PostgreSQL DataRow in place.
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_masking_test.cpp -o /tmp/authnull_masking_test && /tmp/authnull_masking_test
//
// Exits non-zero on any failure.
#include "authnull_masking.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

static void expect(bool ok, const char* what) {
	if (!ok) {
		std::fprintf(stderr, "FAIL %s\n", what);
		failures++;
	}
}

using Policy = std::map<std::string, std::vector<std::string>>;
using Cols = std::vector<AuthnullResultColumn>;

static std::string maskString(const std::vector<bool>& m) {
	std::string s;
	for (bool b : m) s += b ? 'M' : '.';
	return s;
}

static void columns(const Policy& p, const Cols& cols, const std::string& sql, const std::string& want, const char* why) {
	std::string got = maskString(authnullMaskColumns(p, cols, sql));
	if (got != want) {
		std::fprintf(stderr, "FAIL %s\n  sql: %s\n  got %s, want %s\n", why, sql.c_str(), got.c_str(), want.c_str());
		failures++;
	}
}

// A DataRow: 'D', int32 length (itself included, the type byte not), int16 count, then per column
// an int32 length (-1 = NULL) and the bytes.
static std::vector<uint8_t> dataRow(const std::vector<const char*>& values) {
	std::vector<uint8_t> body;
	auto put32 = [&](int32_t v) { for (int s = 24; s >= 0; s -= 8) body.push_back(static_cast<uint8_t>((static_cast<uint32_t>(v) >> s) & 0xff)); };
	body.push_back(static_cast<uint8_t>(values.size() >> 8));
	body.push_back(static_cast<uint8_t>(values.size() & 0xff));
	for (const char* v : values) {
		if (!v) { put32(-1); continue; }
		std::string s(v);
		put32(static_cast<int32_t>(s.size()));
		body.insert(body.end(), s.begin(), s.end());
	}
	std::vector<uint8_t> msg = {'D'};
	uint32_t len = static_cast<uint32_t>(body.size() + 4);
	for (int s = 24; s >= 0; s -= 8) msg.push_back(static_cast<uint8_t>((len >> s) & 0xff));
	msg.insert(msg.end(), body.begin(), body.end());
	return msg;
}

int main() {
	const Policy orders = {{"orders", {"amount", "Card_Number"}}, {"customers", {}}};
	const AuthnullResultColumn id{"id", true, false}, amount{"amount", true, false}, status{"status", true, false};

	// --- which columns ---
	columns(orders, {id, amount, status}, "select * from orders", ".M.", "a masked column by name");
	columns(orders, {{"card_number", true, false}}, "select card_number from orders", "M", "names compare in any case");
	columns(orders, {{"AMOUNT", true, false}}, "select \"AMOUNT\" from orders", "M", "a column named in capitals");
	columns(orders, {id, {"a", true, false}}, "select id, amount as a from orders", ".M", "an alias with AS");
	columns(orders, {id, {"a", true, false}}, "select o.id, o.amount a from orders o", ".M", "an alias without AS, qualified");
	columns(orders, {id, {"x", true, false}}, "select id, x from (select id, amount as x from orders) s", ".M", "an alias inside a subquery");
	columns(orders, {{"?column?", false, false}}, "select amount * 1 from orders", "M", "an expression over a masked column");
	columns(orders, {{"sum", false, false}}, "select sum(amount) from orders", "M", "an aggregate over a masked column");
	columns(orders, {{"amount", false, false}}, "select amount::text from orders", "M", "a cast keeps the name");
	columns(orders, {{"count", false, false}}, "select count(*) from orders", ".", "an expression that mentions no masked column");
	columns(orders, {id, status}, "select id, status from orders where amount > 10", "..", "a masked column only in WHERE leaves table columns alone");
	columns({}, {id, amount}, "select id, amount from orders", "..", "no policy, nothing masked");
	columns({{"orders", {}}}, {id, amount}, "select id, amount from orders", "..", "a table with no masked columns");
	columns(orders, {{"amount_note", true, false}}, "select amount_note from orders", ".", "a longer name that only starts the same");
	columns(orders, {{"label", false, false}}, "select 'amount' as label", ".", "the word only inside a string");
	columns(orders, {id, amount}, "select id, amount from orders; select 1", ".M", "several statements");
	columns(orders, {amount, status}, "select amount, status from orders", "M.", "the column after a masked one is not its alias");
	columns(orders, {id, amount, status}, "select o.id, o.amount, o.status from orders o", ".M.", "qualified columns in a list");

	// --- MySQL: the field metadata gives each column's source table and column (org_table, org_name) ---
	{
		const Policy items = {{"orders", {"item"}}};
		auto my = [&](const Cols& cols, const std::string& sql, const std::string& want, const char* why) {
			std::string got = maskString(authnullMaskColumns(items, cols, sql, AuthnullDialect::MySQL));
			if (got != want) {
				std::fprintf(stderr, "FAIL mysql: %s\n  sql: %s\n  got %s, want %s\n", why, sql.c_str(), got.c_str(), want.c_str());
				failures++;
			}
		};
		auto col = [](const char* name, const char* orgName) { return AuthnullResultColumn{name, true, false, orgName}; };
		auto expr = [](const char* name) { return AuthnullResultColumn{name, false, false, ""}; };
		const AuthnullResultColumn myId = col("id", "id"), myItem = col("item", "item"), myStatus = col("status", "status");

		my({myId, myItem, myStatus}, "SELECT id, item, status FROM orders", ".M.", "a plain column");
		my({myId, myItem}, "SELECT * FROM orders", ".M", "SELECT *");
		my({col("a", "item")}, "SELECT item AS a FROM orders", "M", "an alias");
		my({col("a", "item")}, "SELECT o.item a FROM orders o JOIN customers c ON c.id = o.customer_id", "M", "an alias in a join");
		my({col("a", "item")}, "SELECT item 'a' FROM orders", "M", "a string alias: the source column says it");
		my({col("a", "item")}, "SELECT (item) AS a FROM orders", "M", "a parenthesised column: the source column says it");
		// Metadata as MySQL 8.0 sends it: a derived table's column names its base table but gives the
		// alias as org_name; a derived expression and a UNION have no org_table.
		my({col("x", "x")}, "SELECT x FROM (SELECT item AS x FROM orders) s", "M", "a derived table's alias");
		my({expr("x")}, "SELECT x FROM (SELECT CONCAT(item,'') AS x FROM orders) s", "M", "a derived table's expression");
		my({expr("id")}, "SELECT id FROM t UNION SELECT item FROM orders", "M", "a UNION");
		my({expr("CONCAT(item,'')")}, "SELECT CONCAT(item,'') FROM orders", "M", "CONCAT");
		my({expr("UPPER(item)")}, "SELECT UPPER(item) FROM orders", "M", "UPPER");
		my({expr("HEX(item)")}, "SELECT HEX(item) FROM orders", "M", "HEX");
		my({expr("GROUP_CONCAT(item)")}, "SELECT GROUP_CONCAT(item) FROM orders", "M", "GROUP_CONCAT");
		my({expr("LENGTH(item)")}, "SELECT LENGTH(item) FROM orders", "M", "LENGTH");
		my({expr("x"), myId}, "SELECT CONCAT(o.`item`, '') AS x, id FROM orders o", "M.", "an expression over a backticked column, renamed");
		my({expr("CONCAT(\"item\", '')")}, "SELECT CONCAT(\"item\", '') FROM orders", "M", "a double-quoted name (ANSI_QUOTES)");
		my({expr("UPPER(/*!item*/)")}, "SELECT UPPER(/*!item*/) FROM orders", "M", "inside an executable comment");
		my({expr("COUNT(*)")}, "SELECT COUNT(*) FROM orders", ".", "COUNT(*) that mentions no masked column");
		my({expr("UPPER(status)")}, "SELECT UPPER(status) FROM orders # item", ".", "a mention only in a comment");
		my({expr("COUNT(*)")}, "SELECT COUNT(*) FROM orders WHERE item = 'x'", "M", "an expression when the query mentions the column");
		my({myId}, "SELECT id FROM orders WHERE item = 'x'", ".", "a table column is not masked for a mention in WHERE");
		my({expr("LENGTH(status)")}, "SELECT LENGTH(status) FROM orders WHERE note = 'unterminated", "M", "a query that cannot be read masks expressions");
		my({expr("label")}, "SELECT 'item' AS label FROM orders", ".", "a '...' string is a string, ANSI_QUOTES or not");
		my({col("z", "z")}, "SELECT z FROM (SELECT CONCAT(item, '') z FROM orders) s", "M", "a derived table's alias of an expression");
		my({col("z", "z")}, "SELECT z FROM (SELECT id, CASE WHEN item = 'x' THEN 1 END z FROM orders) s", "M", "an alias after CASE ... END");
		my({col("x", "x")}, "SELECT x FROM (SELECT item FROM orders) AS t(x)", "M", "a derived table's column list");
		my({col("b", "b")}, "WITH c (a, b) AS (SELECT id, item FROM orders) SELECT b FROM c", "M", "a CTE's column list");
		my({col("q", "q")}, "SELECT q FROM (SELECT q FROM (SELECT item AS q FROM orders) a) b", "M", "an alias given deeper in the query");
	}

	// --- PostgreSQL: whole-row references and column lists (the row description says no more) ---
	{
		const Policy items = {{"orders", {"item"}}};
		columns(items, {{"o", true, false}}, "SELECT o FROM orders o", "M", "a whole-row reference");
		columns(items, {{"orders", true, false}}, "SELECT orders FROM orders", "M", "a whole-row reference by the table's name");
		columns(items, {{"row_to_json", false, false}}, "SELECT row_to_json(o) FROM orders o", "M", "row_to_json of the row");
		columns(items, {{"row_to_json", false, false}}, "SELECT row_to_json(o.*) FROM orders o", "M", "row_to_json of o.*");
		columns(items, {{"o", false, false}}, "SELECT o::text FROM orders AS o", "M", "the row cast to text");
		columns(items, {{"to_jsonb", false, false}}, "SELECT to_jsonb(orders) FROM public.orders", "M", "to_jsonb of the table's row");
		columns(items, {{"x", true, false}}, "SELECT x FROM (SELECT item FROM orders) t(x)", "M", "a derived table's column list");
		columns(items, {{"b", true, false}}, "SELECT b FROM orders o(a, b)", "M", "a table alias's column list");
		columns(items, {{"s", false, false}}, "SELECT s FROM (SELECT * FROM orders) s", "M", "a derived table's whole row");
		columns(items, {{"c", false, false}}, "WITH c AS (SELECT * FROM orders) SELECT c FROM c", "M", "a CTE's whole row");
		columns(items, {{"id", true, false}, {"count", false, false}}, "SELECT id, count(*) FROM orders o GROUP BY id", "..",
			"no whole-row reference: nothing more masked");
		columns(items, {{"x", true, false}}, "SELECT x FROM (SELECT id FROM customers) t(x)", ".", "a column list where nothing is masked");
	}

	// --- refusing a query that tests a masked value without returning it ---
	{
		const Policy items = {{"orders", {"item"}}, {"customers", {}}};
		auto refused = [&](AuthnullDialect d, const std::string& sql, bool want, const char* why) {
			const bool got = authnullMaskRefused(items, sql, d);
			if (got != want) {
				std::fprintf(stderr, "FAIL refusal (%s): %s\n  sql: %s\n  got %s\n", d == AuthnullDialect::MySQL ? "mysql" : "pg",
					why, sql.c_str(), got ? "refused" : "allowed");
				failures++;
			}
		};
		for (AuthnullDialect d : {AuthnullDialect::MySQL, AuthnullDialect::Postgres}) {
			// Allowed: the masked value only goes out, masked.
			refused(d, "SELECT id, item FROM orders WHERE id = 1", false, "the column in the select list");
			refused(d, "SELECT * FROM orders ORDER BY id", false, "SELECT * ordered by another column");
			refused(d, "SELECT item AS a FROM orders WHERE id = 1", false, "an alias");
			refused(d, "SELECT o.item a FROM orders o JOIN orders p ON p.id = o.id WHERE o.id = 1", false, "a join on another column");
			refused(d, "SELECT x FROM (SELECT item AS x FROM orders) s", false, "a derived table");
			refused(d, "SELECT UPPER(item), CONCAT(item, '') FROM orders", false, "expressions in the select list");
			refused(d, "SELECT (SELECT item FROM orders LIMIT 1)", false, "a scalar subquery in the select list");
			refused(d, "SELECT CASE WHEN item = 'x' THEN 1 END AS flag FROM orders", false, "a test in the select list: its result is masked");
			refused(d, "WITH c AS (SELECT id, item FROM orders) SELECT * FROM c WHERE id > 1", false, "a CTE, filtered on another column");
			refused(d, "SELECT COUNT(*) FROM orders", false, "COUNT(*)");
			refused(d, "SELECT COUNT(*) FROM (SELECT * FROM orders) cnt", false, "a client's row count");
			refused(d, "SELECT id FROM orders UNION ALL SELECT item FROM orders", false, "UNION ALL compares nothing");
			refused(d, "INSERT INTO orders (id, item) VALUES (9, 'q')", false, "writing the masked column");
			refused(d, "UPDATE orders SET item = 'q' WHERE id = 9", false, "setting the masked column");
			refused(d, "DELETE FROM orders WHERE id = 9", false, "DELETE on another column");
			refused(d, "INSERT INTO archive SELECT id, note FROM orders WHERE id = 1", false, "INSERT ... SELECT of other columns");
			refused(d, "SELECT id FROM customers WHERE item = 'x'", false, "no table with masked columns: nothing masked to test");
			refused(d, "SELECT id FROM orders WHERE note = 'item'", false, "the word only in a string");
			refused(d, "SELECT * FROM orders o JOIN customers c ON c.id = o.customer_id", false, "a join");
			refused(d, "SELECT EXTRACT(YEAR FROM created) FROM orders", false, "FROM inside a function call");
			refused(d, "SELECT id FROM orders WHERE item = 'x' OR note = 'unterminated", true, "a query that cannot be read");

			// Refused: the masked value decides which rows, how many, or in what order.
			refused(d, "SELECT id FROM orders WHERE item = 'x'", true, "WHERE");
			refused(d, "SELECT COUNT(*) FROM orders WHERE item LIKE 'x%'", true, "WHERE LIKE");
			refused(d, "SELECT id FROM orders o WHERE o.item = 'x'", true, "a qualified name");
			refused(d, "SELECT id FROM orders ORDER BY item", true, "ORDER BY");
			refused(d, "SELECT COUNT(*) FROM orders GROUP BY item", true, "GROUP BY");
			refused(d, "SELECT COUNT(*) FROM orders GROUP BY id HAVING MAX(item) > 'm'", true, "HAVING");
			refused(d, "SELECT a.id FROM orders a JOIN orders b ON a.item = b.item", true, "JOIN ... ON");
			refused(d, "SELECT a.id FROM orders a JOIN orders b USING (item)", true, "JOIN ... USING");
			refused(d, "SELECT a.id FROM orders a NATURAL JOIN archive b", true, "NATURAL JOIN");
			refused(d, "SELECT id, ROW_NUMBER() OVER (ORDER BY item) FROM orders", true, "a window's ORDER BY");
			refused(d, "SELECT id, COUNT(*) OVER (PARTITION BY item) FROM orders", true, "PARTITION BY");
			refused(d, "SELECT id FROM orders WHERE id IN (SELECT id FROM orders WHERE item = 'x')", true, "a subquery's WHERE");
			refused(d, "SELECT id FROM customers WHERE name IN (SELECT item FROM orders)", true, "a subquery's select list read by WHERE");
			refused(d, "SELECT EXISTS (SELECT 1 FROM orders WHERE item = 'x')", true, "EXISTS in the select list");
			refused(d, "SELECT id FROM (SELECT id, item AS z FROM orders) s WHERE z = 'x'", true, "an alias of the masked column");
			refused(d, "SELECT id FROM (SELECT id, UPPER(item) z FROM orders) s WHERE z = 'X'", true, "an alias of an expression over it");
			refused(d, "SELECT id FROM (SELECT id, q FROM (SELECT id, item AS q FROM orders) a) b WHERE q = 'x'", true, "an alias given deeper");
			refused(d, "WITH c AS (SELECT id, item AS z FROM orders) SELECT id FROM c WHERE z = 'x'", true, "a CTE's alias");
			refused(d, "WITH c (a, b) AS (SELECT id, item FROM orders) SELECT a FROM c WHERE b = 'x'", true, "a CTE's column list");
			refused(d, "SELECT 1 FROM (SELECT item FROM orders) AS t(x) WHERE x = 'a'", true, "a derived table's column list");
			refused(d, "SELECT item AS z FROM orders ORDER BY z", true, "ORDER BY a select-list alias");
			refused(d, "SELECT id, item FROM orders ORDER BY 2", true, "ORDER BY its position");
			refused(d, "SELECT * FROM orders ORDER BY 2", true, "ORDER BY a position of SELECT *");
			refused(d, "SELECT id, o.* FROM orders o ORDER BY 1", false, "ORDER BY a position before SELECT *");
			refused(d, "SELECT id, item FROM orders WHERE id = 1 FOR UPDATE", false, "FOR UPDATE");
			refused(d, "SELECT DISTINCT item FROM orders", true, "DISTINCT");
			refused(d, "SELECT COUNT(*) FROM (SELECT DISTINCT item FROM orders) s", true, "DISTINCT in a derived table");
			refused(d, "SELECT 'x' UNION SELECT item FROM orders", true, "UNION removes duplicates: it compares");
			refused(d, "SELECT 'x' INTERSECT SELECT item FROM orders", true, "INTERSECT");
			refused(d, "SELECT 'x' EXCEPT SELECT item FROM orders", true, "EXCEPT");
			refused(d, "INSERT INTO archive (v) SELECT item FROM orders", true, "INSERT ... SELECT copies it out of masking");
			refused(d, "INSERT INTO archive SELECT * FROM orders", true, "INSERT ... SELECT * copies it without naming it");
			refused(d, "UPDATE orders SET note = item WHERE id = 1", true, "UPDATE ... SET x = c");
			refused(d, "UPDATE orders SET note = CONCAT('a', item) WHERE id = 1", true, "UPDATE ... SET x = f(.., c)");
			refused(d, "UPDATE orders SET note = 'a' WHERE item = 'x'", true, "UPDATE ... WHERE");
			refused(d, "DELETE FROM orders WHERE item = 'x'", true, "DELETE ... WHERE");
			refused(d, "CREATE TABLE t2 AS SELECT item FROM orders", true, "CREATE ... AS SELECT");
			refused(d, "SELECT item INTO t2 FROM orders", true, "SELECT ... INTO");
			refused(d, "EXPLAIN SELECT id FROM orders WHERE item = 'x'", true, "EXPLAIN");
			refused(d, "SELECT id FROM orders WHERE id = 1; SELECT id FROM orders WHERE item = 'x'", true, "the second statement");
		}

		const AuthnullDialect my = AuthnullDialect::MySQL, pg = AuthnullDialect::Postgres;
		refused(my, "SELECT id FROM orders WHERE `item` = 'x'", true, "a backticked name");
		refused(my, "SELECT id FROM `shop`.`orders` WHERE \"item\" = 'x'", true, "a \"...\" name (ANSI_QUOTES)");
		refused(my, "SELECT id FROM orders WHERE /*!item*/ = 'x'", true, "inside an executable comment");
		refused(my, "SELECT id FROM orders # WHERE item = 'x'", false, "only in a comment");
		refused(my, "SELECT @v := item FROM orders", true, "a user variable keeps the value");
		refused(my, "SELECT item INTO @v FROM orders LIMIT 1", true, "SELECT ... INTO @v");
		refused(my, "SELECT id FROM orders WHERE item = ?", true, "a prepared statement's placeholder");
		refused(my, "INSERT INTO orders (id, item) VALUES (9, 'q') ON DUPLICATE KEY UPDATE item = VALUES(item)", false, "an upsert of the masked column");
		refused(my, "INSERT INTO orders (id) VALUES (9) ON DUPLICATE KEY UPDATE note = item", true, "an upsert copying it");
		refused(my, "INSERT INTO orders SET id = 9, item = 'q'", false, "INSERT ... SET");
		refused(my, "INSERT INTO archive TABLE orders", true, "INSERT ... TABLE");
		refused(my, "TABLE orders", false, "TABLE: SELECT * to the client");
		refused(my, "SHOW CREATE TABLE orders", false, "SHOW CREATE TABLE");
		refused(my, "SHOW FULL COLUMNS FROM `orders` FROM `shop`", false, "SHOW COLUMNS");
		refused(my, "SELECT * FROM shop.orders LIMIT 0, 200", false, "a client's first page");

		refused(pg, "SELECT id FROM orders o WHERE o::text LIKE '%x%'", true, "a whole-row reference in WHERE");
		refused(pg, "SELECT id FROM orders o WHERE row_to_json(o)->>'item' = 'x'", true, "row_to_json in WHERE");
		refused(pg, "SELECT key FROM orders o, jsonb_each_text(to_jsonb(o)) e", true, "the row into a function in FROM");
		refused(pg, "SELECT id FROM (SELECT * FROM orders) s WHERE s::text LIKE '%x%'", true, "a derived table's row in WHERE");
		refused(pg, "INSERT INTO orders (id, item) VALUES (9, 'q') ON CONFLICT (id) DO UPDATE SET item = EXCLUDED.item", false, "ON CONFLICT setting it");
		refused(pg, "UPDATE orders SET note = 'a' WHERE id = 1 RETURNING item", false, "RETURNING: masked on the way out");
		refused(pg, "WITH d AS (DELETE FROM orders WHERE item = 'x' RETURNING id) SELECT count(*) FROM d", true, "a writing CTE's WHERE");
		refused(pg, "WITH c AS (SELECT * FROM orders) INSERT INTO archive SELECT * FROM c", true, "a write after a CTE");
		refused(pg, "SELECT DISTINCT ON (id) id, item FROM orders ORDER BY id", false, "DISTINCT ON compares only its list");
		refused(pg, "SELECT DISTINCT ON (item) id FROM orders", true, "DISTINCT ON the masked column");
		refused(pg, "SELECT o FROM orders o", false, "a whole row in the select list: masked");
		refused(pg, "SELECT x FROM (SELECT item FROM orders) t(x)", false, "a column list in the select list: masked");
		refused(pg, "SELECT id FROM orders WHERE note = $1", false, "a parameter");
		refused(pg, "TABLE orders", false, "TABLE");
		refused(pg, "SELECT * FROM public.orders ORDER BY id ASC LIMIT 100", false, "pgAdmin's first rows");
		refused(pg, "SELECT x.* FROM public.orders x", false, "DBeaver's data view");
		refused(pg, "SELECT id FROM orders WHERE item = 'x' AND note = $$it's$$", true, "with a dollar-quoted string");
	}

	// --- MySQL binary-protocol rows (prepared statements) ---
	{
		// 0x00, NULL bitmap (offset 2 bits), then the non-NULL values. Types: LONG, VAR_STRING, DOUBLE,
		// DATETIME, VAR_STRING; the last is NULL.
		const std::vector<int> types = {3, 253, 5, 12, 253};
		std::vector<uint8_t> row = {0x00, 0x40, 7, 0, 0, 0, 3, 'a', 'b', 'c', 0, 0, 0, 0, 0, 0, 0xf8, 0x3f,
			7, 0xea, 0x07, 11, 24, 10, 30, 0};
		const std::vector<uint8_t> before = row;
		size_t n = authnullMaskBinaryRow(row.data(), row.size(), {false, true, true, true, false}, types);
		const std::vector<uint8_t> want = {0x00, 0x70, 7, 0, 0, 0, 3, '*', '*', '*'};
		expect(std::vector<uint8_t>(row.begin(), row.begin() + static_cast<long>(n)) == want,
			"binary row: a string is starred, a double and a datetime become NULL, NULL stays NULL");

		row = before;
		n = authnullMaskBinaryRow(row.data(), row.size(), {false, false, false, false, false}, types);
		expect(n == before.size() && row == before, "binary row: nothing masked, nothing changes");

		row = before;
		n = authnullMaskBinaryRow(row.data(), row.size() - 3, {false, true, false, false, false}, types);
		expect(n == 2 && row[0] == 0 && row[1] == 0x7c, "binary row: one that cannot be read comes back all NULL");

		// A 300-byte string: its length is written 0xfc + 2 bytes.
		std::vector<uint8_t> big = {0x00, 0x00, 0xfc, 0x2c, 0x01};
		big.insert(big.end(), 300, 'v');
		n = authnullMaskBinaryRow(big.data(), big.size(), {true}, {252});
		expect(n == 305 && big[4] == 0x01 && big[5] == '*' && big[304] == '*', "binary row: a long blob is starred, its length kept");
	}

	// --- masking a DataRow in place ---
	{
		std::vector<uint8_t> row = dataRow({"1", "37.50", nullptr, "paid"});
		std::vector<uint8_t> before = row;
		bool ok = authnullMaskDataRow(row.data(), row.size(), {false, true, true, false}, {});
		expect(ok, "a well-formed row is masked");
		std::vector<uint8_t> want = dataRow({"1", "*****", nullptr, "paid"});
		expect(row == want, "masked value is * of the same length, NULL stays NULL, others untouched");
		expect(row.size() == before.size(), "the row keeps its length");
	}
	{
		std::vector<uint8_t> row = dataRow({"7", "\x01\x02"});
		authnullMaskDataRow(row.data(), row.size(), {false, true}, {false, true});
		// dataRow stops a C string at NUL: build the zeroed expectation by hand.
		std::vector<uint8_t> want = dataRow({"7", "xx"});
		want[want.size() - 1] = 0;
		want[want.size() - 2] = 0;
		expect(row == want, "a binary-format column is zeroed, not starred");
	}
	{
		std::vector<uint8_t> row = dataRow({"1", "2"});
		std::vector<uint8_t> before = row;
		row[6] = 9; // claims 9 columns
		bool ok = authnullMaskDataRow(row.data(), row.size(), {true, true}, {});
		expect(!ok, "a row that runs past its end is refused");
		std::vector<uint8_t> trunc(before.begin(), before.begin() + 9);
		expect(!authnullMaskDataRow(trunc.data(), trunc.size(), {true, true}, {}), "a truncated row is refused");
		std::vector<uint8_t> notD = before;
		notD[0] = 'T';
		expect(!authnullMaskDataRow(notD.data(), notD.size(), {true, true}, {}), "not a DataRow");
	}
	{
		std::vector<uint8_t> row = dataRow({"1", "37.50"});
		std::vector<uint8_t> before = row;
		expect(authnullMaskDataRow(row.data(), row.size(), {false, false}, {}) && row == before, "nothing to mask, nothing changes");
		expect(authnullMaskDataRow(row.data(), row.size(), {}, {}) && row == before, "no mask at all");
	}

	// --- one value, for the PGresult path ---
	expect(authnullMaskedValue("37.50", 5, false) == "*****", "a text value");
	expect(authnullMaskedValue("ab", 2, true) == std::string(2, '\0'), "a binary value");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("authnull_masking_test: ok\n");
	return 0;
}
