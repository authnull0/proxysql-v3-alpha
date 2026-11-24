// Standalone test for include/authnull_tables.h: a MySQL statement held to a policy's table list.
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_tables_test.cpp -o /tmp/authnull_tables_test && /tmp/authnull_tables_test
//
// Exits non-zero on any failure.
#include "authnull_tables.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

using L = std::vector<std::string>;
static const L ORDERS = {"orders"};
static const std::string DB = "dbmfa_test";

static void permits(const L& tables, const std::string& sql, bool want, const char* why, const std::string& db = DB) {
	bool got = authnullTablesPermitted(tables, db, sql);
	if (got != want) {
		std::fprintf(stderr, "FAIL %s\n  sql: %s\n  got %s, want %s\n", why, sql.c_str(),
			got ? "permitted" : "refused", want ? "permitted" : "refused");
		failures++;
	}
}
static void allowed(const std::string& sql, const char* why) { permits(ORDERS, sql, true, why); }
static void refused(const std::string& sql, const char* why) { permits(ORDERS, sql, false, why); }

static void named(const std::string& sql, const std::string& want, const char* why) {
	bool ok = false;
	auto refs = authnullTablesNamed(sql, ok);
	std::string got;
	for (const auto& r : refs) got += (got.empty() ? "" : " ") + (r.first.empty() ? "" : r.first + ".") + r.second;
	if (!ok) got = "unreadable";
	if (got != want) {
		std::fprintf(stderr, "FAIL %s\n  sql: %s\n  got [%s], want [%s]\n", why, sql.c_str(), got.c_str(), want.c_str());
		failures++;
	}
}

int main() {
	// --- the lab's cases (tables=[orders]) ---
	allowed("SELECT * FROM orders", "the listed table");
	refused("SELECT * FROM customers", "an unlisted table");
	refused("SELECT * FROM dbmfa_test.customers", "an unlisted table, qualified");
	refused("SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id", "a JOIN with an unlisted table");

	// --- names ---
	allowed("select * from ORDERS", "case-insensitive");
	allowed("SELECT * FROM `orders`", "backticks");
	allowed("SELECT * FROM `dbmfa_test`.`orders` LIMIT 0, 200", "qualified, backticks (DBeaver)");
	allowed("SELECT * FROM DBMFA_TEST.orders", "qualified, other case");
	refused("SELECT * FROM otherdb.orders", "the listed name in another database");
	refused("SELECT * FROM `customers`", "unlisted, backticks");
	refused("SELECT * FROM `dbmfa_test`.customers", "unlisted, quoted database");
	refused("SELECT * FROM \"customers\"", "a string where a table goes (ANSI_QUOTES): unreadable");
	permits({"dbmfa_test.orders"}, "SELECT * FROM orders", true, "list entry qualified with the session's database");
	permits({"otherdb.orders"}, "SELECT * FROM orders", false, "list entry in another database grants nothing here");
	permits({" Orders "}, "SELECT * FROM orders", true, "list entry trimmed, case-insensitive");
	permits({}, "SELECT * FROM customers", true, "no list: no restriction");
	permits({"orders", "customers"}, "SELECT * FROM orders JOIN customers USING (id)", true, "both listed");

	// --- joins ---
	allowed("SELECT * FROM orders a JOIN orders b ON a.id = b.id", "self join");
	refused("SELECT * FROM orders LEFT JOIN customers ON 1", "LEFT JOIN");
	refused("SELECT * FROM orders LEFT OUTER JOIN customers USING (id)", "LEFT OUTER JOIN ... USING");
	refused("SELECT * FROM orders RIGHT JOIN customers ON 1", "RIGHT JOIN");
	refused("SELECT * FROM orders INNER JOIN customers ON 1", "INNER JOIN");
	refused("SELECT * FROM orders CROSS JOIN customers", "CROSS JOIN");
	refused("SELECT * FROM orders NATURAL JOIN customers", "NATURAL JOIN");
	refused("SELECT * FROM orders STRAIGHT_JOIN customers", "STRAIGHT_JOIN");
	allowed("SELECT * FROM orders STRAIGHT_JOIN orders o2", "STRAIGHT_JOIN, listed");
	refused("SELECT * FROM orders WHERE 1 JOIN customers", "a JOIN outside any table list");
	allowed("SELECT STRAIGHT_JOIN * FROM orders", "STRAIGHT_JOIN as a SELECT modifier");
	refused("SELECT * FROM orders, customers", "comma join");
	refused("SELECT * FROM orders o, dbmfa_test.customers c WHERE o.id = c.id", "comma join, qualified, aliases");
	refused("SELECT * FROM orders JOIN orders o2 ON 1 JOIN customers ON 1", "third table");
	refused("SELECT * FROM orders o JOIN orders p ON o.id = p.id, customers", "comma after a join");
	refused("SELECT * FROM orders a JOIN orders b ON a.where = b.id, customers", "reserved word column in ON");
	refused("SELECT * FROM (orders JOIN customers ON 1)", "join in parentheses");
	refused("SELECT * FROM ((customers))", "table in parentheses");
	refused("SELECT * FROM orders JOIN (customers c, orders d) ON 1", "comma join in parentheses");
	allowed("SELECT * FROM orders o USE INDEX (PRIMARY) JOIN orders p FORCE INDEX FOR JOIN (PRIMARY) ON 1", "index hints");
	refused("SELECT * FROM orders USE INDEX (a), IGNORE INDEX (b), customers", "index hint list, then a table");
	allowed("SELECT * FROM orders PARTITION (p0) AS o WHERE o.id = 1", "partition");
	refused("SELECT * FROM orders o JOIN customers c ON c.id = (SELECT 1) WHERE 1", "ON with a subquery");
	refused("SELECT * FROM orders o JOIN orders p ON p.id IN (SELECT id FROM customers)", "subquery inside ON");

	// --- subqueries, derived tables, CTEs ---
	allowed("SELECT x FROM (SELECT id AS x FROM orders) AS customers", "derived-table alias is not a table");
	allowed("SELECT * FROM (SELECT * FROM orders) d (a, b, c)", "derived table with column list");
	refused("SELECT x FROM (SELECT id AS x FROM customers) d", "derived table over an unlisted table");
	refused("SELECT * FROM orders WHERE id IN (SELECT order_id FROM customers)", "subquery in WHERE");
	refused("SELECT (SELECT COUNT(*) FROM customers) FROM orders", "subquery in the select list");
	refused("SELECT * FROM orders WHERE EXISTS (SELECT 1 FROM dbmfa_test.customers)", "EXISTS");
	refused("SELECT * FROM orders WHERE id IN (TABLE customers)", "TABLE subquery");
	refused("SELECT * FROM ((SELECT 1) UNION (SELECT id FROM customers)) d", "union in a derived table");
	refused("SELECT * FROM ((SELECT 1 AS id) d JOIN customers c USING (id))", "derived table joined in parentheses");
	refused("SELECT * FROM orders, LATERAL (SELECT * FROM customers) l", "LATERAL");
	allowed("SELECT * FROM orders o, LATERAL (SELECT * FROM orders p WHERE p.id = o.id) l", "LATERAL, listed");
	allowed("WITH c AS (SELECT * FROM orders) SELECT * FROM c", "CTE name");
	allowed("WITH customers AS (SELECT * FROM orders) SELECT * FROM customers", "CTE shadowing an unlisted name");
	refused("WITH c AS (SELECT * FROM customers) SELECT * FROM c", "CTE over an unlisted table");
	refused("WITH customers AS (SELECT * FROM customers) SELECT * FROM customers", "non-recursive CTE: its own name inside is the table");
	allowed("WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT * FROM r JOIN orders", "recursive CTE");
	allowed("WITH a AS (SELECT * FROM orders), b AS (SELECT * FROM a) SELECT * FROM b", "CTE using an earlier one");
	refused("SELECT * FROM (WITH customers AS (SELECT 1) SELECT * FROM customers) d, customers", "CTE out of scope");
	refused("(WITH customers AS (SELECT 1) SELECT * FROM customers) UNION (SELECT * FROM customers)", "CTE scope ends with its parentheses");
	allowed("SELECT a, COUNT(*) FROM orders GROUP BY a WITH ROLLUP", "WITH ROLLUP is not a CTE");
	refused("SELECT * FROM orders UNION SELECT * FROM customers", "UNION");
	refused("SELECT * FROM orders UNION TABLE customers", "UNION TABLE");
	allowed("SELECT EXTRACT(YEAR FROM created), TRIM(LEADING 'x' FROM note), SUBSTRING(note FROM 2 FOR 3) FROM orders", "FROM inside functions");
	refused("SELECT TRIM(BOTH ' ' FROM (SELECT name FROM customers LIMIT 1))", "subquery inside TRIM");
	allowed("SELECT NTH_VALUE(id, 2) FROM FIRST OVER (ORDER BY id) FROM orders", "NTH_VALUE ... FROM FIRST");
	allowed("SELECT o.from, o.table, o.join FROM orders o", "reserved words after a period are names");
	allowed("SELECT * FROM orders FOR UPDATE", "row lock");
	allowed("SELECT * FROM orders WHERE note = 'from customers'", "a string is not a table");
	allowed("SELECT * FROM orders /* JOIN customers */ -- , customers\n", "comments");
	refused("SELECT * FROM orders /*!50000 JOIN customers */", "executable comment is code");
	allowed("SELECT * FROM orders, JSON_TABLE('[1]', '$[*]' COLUMNS (x INT PATH '$')) AS jt WHERE 0", "JSON_TABLE is not a table");
	refused("SELECT * FROM orders, JSON_TABLE((SELECT doc FROM customers), '$[*]' COLUMNS (x INT PATH '$')) jt", "subquery inside JSON_TABLE");
	allowed("SELECT 1 FROM DUAL", "DUAL");

	// --- writes ---
	allowed("INSERT INTO orders (id) VALUES (1)", "INSERT");
	refused("INSERT INTO customers (id) VALUES (1)", "INSERT into an unlisted table");
	refused("INSERT customers VALUES (1)", "INSERT without INTO");
	refused("INSERT IGNORE INTO dbmfa_test.customers SET id = 1", "INSERT IGNORE ... SET, qualified");
	refused("INSERT INTO orders SELECT * FROM customers", "INSERT ... SELECT from an unlisted table");
	refused("INSERT INTO orders TABLE customers", "INSERT ... TABLE");
	refused("INSERT INTO orders VALUES (1) ON DUPLICATE KEY UPDATE n = (SELECT MAX(n) FROM customers)", "subquery in ON DUPLICATE KEY UPDATE");
	allowed("INSERT INTO orders SELECT * FROM orders o ON DUPLICATE KEY UPDATE n = 1", "INSERT ... SELECT ... ON DUPLICATE");
	refused("REPLACE INTO customers VALUES (1)", "REPLACE");
	allowed("REPLACE orders VALUES (1)", "REPLACE, listed");
	allowed("UPDATE orders SET n = 1 WHERE id = 2", "UPDATE");
	refused("UPDATE customers SET n = 1", "UPDATE an unlisted table");
	refused("UPDATE LOW_PRIORITY orders o JOIN customers c ON c.id = o.id SET o.n = c.n", "multi-table UPDATE (JOIN)");
	refused("UPDATE orders, customers SET orders.n = customers.n", "multi-table UPDATE (comma)");
	refused("UPDATE orders SET n = (SELECT n FROM customers LIMIT 1)", "UPDATE with a subquery");
	allowed("DELETE FROM orders WHERE id = 1", "DELETE");
	refused("DELETE FROM customers", "DELETE from an unlisted table");
	allowed("DELETE FROM orders AS o WHERE o.id = 1", "DELETE with an alias");
	refused("DELETE o FROM orders o JOIN customers c ON c.id = o.id", "multi-table DELETE");
	refused("DELETE o, c FROM orders o, customers c WHERE o.id = c.id", "multi-table DELETE, comma");
	refused("DELETE FROM o USING orders AS o JOIN customers c ON c.id = o.id", "multi-table DELETE ... USING");
	allowed("DELETE FROM a, b USING orders AS a JOIN orders AS b USING (id)", "DELETE ... USING, aliases of a listed table");
	refused("DELETE FROM orders WHERE id IN (SELECT id FROM customers)", "DELETE with a subquery");
	allowed("WITH c AS (SELECT id FROM orders) DELETE FROM orders WHERE id IN (SELECT id FROM c)", "WITH ... DELETE");
	refused("WITH c AS (SELECT id FROM orders) UPDATE customers SET n = 1", "WITH ... UPDATE of an unlisted table");
	allowed("TRUNCATE TABLE orders", "TRUNCATE");
	refused("TRUNCATE customers", "TRUNCATE an unlisted table");

	// --- metadata ---
	allowed("SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbmfa_test'", "information_schema");
	allowed("SELECT t.TABLE_NAME FROM INFORMATION_SCHEMA.TABLES t JOIN information_schema.columns c USING (TABLE_NAME)", "information_schema join");
	refused("SELECT * FROM information_schema.TABLES, customers", "information_schema with an unlisted table");
	refused("SELECT * FROM mysql.user", "mysql schema");
	refused("SELECT * FROM performance_schema.threads", "performance_schema");
	refused("SELECT * FROM sys.session", "sys schema");
	permits({"user"}, "SELECT * FROM mysql.user", false, "mysql schema even when the name is listed");
	permits({"user"}, "SELECT * FROM user", false, "mysql schema even as the session's database", "mysql");
	allowed("SHOW TABLES", "SHOW TABLES");
	allowed("SHOW FULL TABLES FROM `dbmfa_test` LIKE 'o%'", "SHOW FULL TABLES");
	allowed("SHOW DATABASES", "SHOW DATABASES");
	allowed("SHOW TABLE STATUS FROM dbmfa_test", "SHOW TABLE STATUS");
	allowed("SHOW FULL COLUMNS FROM `orders` FROM `dbmfa_test`", "SHOW COLUMNS, listed");
	refused("SHOW COLUMNS FROM customers", "SHOW COLUMNS, unlisted");
	refused("SHOW COLUMNS IN orders FROM otherdb", "SHOW COLUMNS in another database");
	refused("SHOW INDEX FROM dbmfa_test.customers", "SHOW INDEX, unlisted");
	allowed("SHOW KEYS IN orders", "SHOW KEYS, listed");
	allowed("SHOW CREATE TABLE `dbmfa_test`.`orders`", "SHOW CREATE TABLE, listed");
	refused("SHOW CREATE TABLE customers", "SHOW CREATE TABLE, unlisted");
	refused("SHOW TABLES WHERE Tables_in_dbmfa_test IN (SELECT name FROM customers)", "SHOW with a subquery");
	allowed("DESCRIBE orders", "DESCRIBE, listed");
	refused("DESC customers", "DESC, unlisted");
	allowed("DESC orders id", "DESC with a column");
	refused("EXPLAIN dbmfa_test.customers", "EXPLAIN of a table");
	allowed("EXPLAIN SELECT * FROM orders", "EXPLAIN SELECT, listed");
	refused("EXPLAIN FORMAT=JSON SELECT * FROM customers", "EXPLAIN FORMAT=JSON of an unlisted table");
	refused("EXPLAIN ANALYZE SELECT * FROM orders JOIN customers", "EXPLAIN ANALYZE");
	refused("EXPLAIN FOR CONNECTION 12", "EXPLAIN FOR CONNECTION");

	// --- client housekeeping and statements without tables ---
	allowed("SELECT @@version_comment LIMIT 1", "SELECT @@var");
	allowed("/* mysql-connector-j */ SELECT @@session.auto_increment_increment AS a, @@character_set_client", "driver probe");
	allowed("SELECT DATABASE(), USER(), NOW()", "SELECT without FROM");
	allowed("SHOW VARIABLES LIKE 'lower_case%'", "SHOW VARIABLES");
	allowed("SHOW WARNINGS", "SHOW WARNINGS");
	allowed("SET NAMES utf8mb4", "SET NAMES");
	allowed("SET autocommit = 1, sql_mode = 'STRICT_TRANS_TABLES'", "SET variables");
	allowed("SET @table = 1", "user variable named table");
	allowed("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED", "SET TRANSACTION");
	refused("SET @n = (SELECT COUNT(*) FROM customers)", "SET with a subquery");
	allowed("USE dbmfa_test", "USE");
	allowed("BEGIN", "BEGIN");
	allowed("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY", "START TRANSACTION, modes with a comma");
	allowed("COMMIT", "COMMIT");
	allowed("ROLLBACK TO SAVEPOINT s1", "ROLLBACK TO SAVEPOINT");
	allowed("SELECT 1; SELECT * FROM orders;", "two statements, listed");
	refused("SELECT 1; SELECT * FROM customers", "second statement unlisted");
	allowed("", "empty");

	// --- refused: can't be read with confidence, or reaches past the list ---
	refused("CALL report()", "CALL");
	refused("DO (SELECT 1)", "DO");
	refused("HANDLER customers OPEN", "HANDLER");
	refused("LOCK TABLES orders READ", "LOCK TABLES");
	refused("PREPARE s FROM 'SELECT * FROM customers'", "PREPARE");
	refused("CREATE TABLE x AS SELECT * FROM orders", "DDL");
	refused("DROP TABLE orders", "DROP");
	refused("LOAD DATA INFILE '/tmp/x' INTO TABLE orders", "LOAD DATA");
	refused("SELECT * FROM orders WHERE note = 'x", "unterminated string");
	refused("SELECT * FROM (orders", "unbalanced parenthesis");
	refused("SELECT * FROM orders o customers", "unexpected token after a table");
	refused("SELECT * FROM", "FROM without a table");

	// --- what is read ---
	named("SELECT * FROM a JOIN db.b ON 1, `C` x LEFT JOIN (d, e) ON 1", "a db.b c d e", "every kind of reference");
	named("UPDATE a JOIN b USING (id) SET a.x = (SELECT y FROM c)", "a b c", "UPDATE");
	named("DELETE FROM x, y USING a AS x JOIN b AS y", "a b", "DELETE ... USING");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("authnull_tables_test: all passed\n");
	return 0;
}
