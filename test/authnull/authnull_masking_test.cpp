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
