// Standalone test for include/authnull_pg_extended.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_pg_extended_test.cpp -o /tmp/authnull_pg_extended_test && /tmp/authnull_pg_extended_test
#include "authnull_pg_extended.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace authnull_pgx;

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}

static std::string show(const std::string& b) { // message types, for failure output
	std::string out;
	for (size_t i = 0; i + 5 <= b.size();) {
		const uint32_t len = (uint32_t((unsigned char)b[i + 1]) << 24) | (uint32_t((unsigned char)b[i + 2]) << 16) |
			(uint32_t((unsigned char)b[i + 3]) << 8) | uint32_t((unsigned char)b[i + 4]);
		out += b[i];
		i += 1 + len;
	}
	return out;
}

// ---- Client messages

static std::string cstr(const std::string& s) { return s + std::string(1, '\0'); }

static std::string Parse(const std::string& name, const std::string& sql, const std::vector<uint32_t>& types = {}) {
	std::string b = cstr(name) + cstr(sql);
	put16(b, static_cast<uint16_t>(types.size()));
	for (uint32_t t : types) put32(b, t);
	return b;
}

struct V { bool null; std::string text; };

static std::string Bind(const std::string& portal, const std::string& stmt, const std::vector<V>& vals,
		const std::vector<uint16_t>& formats = {}, const std::vector<uint16_t>& resultFormats = {0}) {
	std::string b = cstr(portal) + cstr(stmt);
	put16(b, static_cast<uint16_t>(formats.size()));
	for (uint16_t f : formats) put16(b, f);
	put16(b, static_cast<uint16_t>(vals.size()));
	for (const V& v : vals) {
		if (v.null) { put32(b, 0xffffffffu); continue; }
		put32(b, static_cast<uint32_t>(v.text.size()));
		b += v.text;
	}
	put16(b, static_cast<uint16_t>(resultFormats.size()));
	for (uint16_t f : resultFormats) put16(b, f);
	return b;
}

static std::string Describe(char of, const std::string& name) { return std::string(1, of) + cstr(name); }
static std::string Execute(const std::string& portal) { std::string b = cstr(portal); put32(b, 0); return b; }
static std::string Close(char of, const std::string& name) { return std::string(1, of) + cstr(name); }

static Extended::Action send(Extended& x, char type, const std::string& body = std::string(), bool queued = false) {
	return x.on(type, reinterpret_cast<const unsigned char*>(body.data()), body.size(), queued);
}

// ---- Backend messages
static const std::string T = message('T', std::string("\0\1x\0", 4) + std::string(18, '\0'));
static const std::string Dr = message('D', std::string("\0\1\0\0\0\1" "5", 7));
static const std::string C_SELECT = message('C', cstr("SELECT 1"));
static const std::string C_INSERT = message('C', cstr("INSERT 0 1"));
static const std::string Z = message('Z', "I");
static const std::string E = errorResponse("42P01", "relation does not exist");

static bool isError(const std::string& b, const std::string& sqlstate) {
	const std::string types = show(b);
	return !types.empty() && types.back() == 'E' && b.find("C" + sqlstate + std::string(1, '\0')) != std::string::npos;
}

// A $n inside a value must never show as a parameter of the SQL it ends up in, read either way.
static void injectionProof(const std::string& v, uint32_t oid) {
	Scan sc = scan("select $1 as x, $2 as y");
	for (const char* tail : {" $5 '$6' $7 -- $8", " $5 '$6' \\' $7 -- $8"}) { // '...' and, with a backslash, $an$...$an$
		std::vector<Value> vals(2);
		vals[0].text = v + tail;
		vals[1].text = "$9";
		const std::string out = substitute("select $1 as x, $2 as y", sc.params, vals, {oid, 0});
		const Scan on = scanAs(out, true), off = scanAs(out, false);
		expect(on.error.empty() && off.error.empty() && on.params.empty() && off.params.empty() && on.statements == 1 &&
			off.statements == 1, "value stays one literal: [" + vals[0].text + "] oid " + std::to_string(oid) + " -> " + out);
	}
}

int main() {
	// ---- literal
	expect(literal("abc") == "'abc'", "plain");
	expect(literal("") == "''", "empty");
	expect(literal("O'Brien") == "'O''Brien'", "quote doubled");
	expect(literal("a\\b") == "$an$a\\b$an$", "backslash: dollar quoted");
	expect(literal("\\$an$") == "$an1$\\$an$$an1$", "tag in the value: another tag");
	expect(literal("\\x$an") == "$an1$\\x$an$an1$", "value ending in the tag's start: another tag");
	expect(literal("\\x$") == "$an$\\x$$an$", "a trailing $ cannot end it early");
	expect(valueSQL(Value{true, ""}, 0) == "NULL", "null");
	expect(valueSQL(Value{true, ""}, 23) == "(NULL::int4)", "typed null");
	expect(valueSQL(Value{false, "42"}, 23) == "('42'::int4)", "typed");
	expect(valueSQL(Value{false, "{1,2}"}, 1007) == "('{1,2}'::int4[])", "array");
	expect(valueSQL(Value{false, "x"}, 99999) == "'x'", "unknown type: bare literal");
	expect(valueSQL(Value{false, "a"}, 18) == "('a'::\"char\")", "\"char\"");

	const char* nasty[] = {"'", "''", "\\", "\\'", "'\\", "\\\\'", "$an$", "x$an", "$an", "$", "$$", "$an1$", "$a$",
		"'; drop table t; --", "/*", "*/", "--", "E'\\x27'", "\xc3\xa9'", "\x82\\", "\x95\\'", "\\$an$'", "$$'$$", "\"", "\";--"};
	for (const char* v : nasty) {
		injectionProof(v, 0);
		injectionProof(v, 25);
	}

	// ---- binary parameters
	{
		auto bin = [](std::initializer_list<int> bytes) { std::string s; for (int b : bytes) s += static_cast<char>(b); return s; };
		std::string out;
		expect(fromBinary(23, bin({0xff, 0xff, 0xff, 0xfe}), out) && out == "-2", "int4");
		expect(fromBinary(20, bin({0, 0, 0, 0, 0xb2, 0xd0, 0x5e, 0}), out) && out == "3000000000", "int8");
		expect(fromBinary(21, bin({0, 5}), out) && out == "5", "int2");
		expect(fromBinary(16, bin({1}), out) && out == "t", "bool");
		expect(fromBinary(701, bin({0x3f, 0xf8, 0, 0, 0, 0, 0, 0}), out) && out == "1.5", "float8: " + out);
		expect(fromBinary(1700, bin({0, 2, 0, 0, 0, 0, 0, 2, 0, 12, 0x13, 0x88}), out) && out == "12.50", "numeric 12.50: " + out);
		expect(fromBinary(1700, bin({0, 1, 0xff, 0xff, 0x40, 0, 0, 4, 0, 12}), out) && out == "-0.0012", "numeric -0.0012: " + out);
		expect(fromBinary(1700, bin({0, 3, 0, 2, 0, 0, 0, 0, 0, 1, 0x09, 0x29, 0x1a, 0x85}), out) && out == "123456789", "numeric 123456789: " + out);
		expect(fromBinary(1082, bin({0, 0, 0x22, 0x79}), out) && out == "2024-02-29", "date: " + out);
		std::string ts;
		const uint64_t t = 8767ULL * 86400000000ULL + 11045000000ULL;
		for (int k = 7; k >= 0; k--) ts += static_cast<char>((t >> (8 * k)) & 0xff);
		expect(fromBinary(1184, ts, out) && out == "2024-01-02 03:04:05.000000+00", "timestamptz: " + out);
		expect(fromBinary(2950, bin({0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}), out) &&
			out == "00112233-4455-6677-8899-aabbccddeeff", "uuid");
		expect(fromBinary(17, bin({0, 0x27, 0x5c}), out) && out == "\\x00275c", "bytea as hex");
		expect(!fromBinary(23, bin({0, 1}), out), "wrong size refused");
		expect(!fromBinary(1007, bin({0}), out), "a short array refused");
		// int2[] {1,NULL,3}: ndim 1, has nulls, int2; dim 3 from 1; then the elements
		expect(fromBinary(1005, bin({0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 21, 0, 0, 0, 3, 0, 0, 0, 1,
			0, 0, 0, 2, 0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2, 0, 3}), out) && out == "{\"1\",NULL,\"3\"}", "int2[]: " + out);
		expect(!fromBinary(1186, bin({0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0}), out), "interval is not read as an array");
		Extended x;
		send(x, 'P', Parse("", "select $1 + $2", {23, 0}));
		send(x, 'B', Bind("", "", {{false, bin({0, 0, 0, 7})}, {false, "1"}}, {1, 0}));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run && x.sql() == "select ('7'::int4) + '1'", "binary int4 parameter: " + x.sql());
	}

	// ---- scan
	{
		Scan s = scan("select * from t where a = $1 and b = $2");
		expect(s.error.empty() && s.params.size() == 2 && s.maxParam == 2 && s.statements == 1, "two params");
		s = scan("select '$1', \"$2\", $$ $3 $$, $tag$ $4 $tag$, E'\\' $5', -- $6\n /* $7 /* $8 */ $9 */ $10");
		expect(s.error.empty() && s.params.size() == 1 && s.params[0].number == 10, "only the $n outside strings, idents, comments: " + s.error);
		s = scan("select U&'$1', b'$2', x'$3', U&\"$4\", n'$5', e'$6' || $7");
		expect(s.error.empty() && s.params.size() == 1 && s.params[0].number == 7, "prefixed strings");
		s = scan("select a$1 from t$2");
		expect(s.error.empty() && s.params.empty(), "$ inside identifiers");
		s = scan("select $1abc");
		expect(!s.error.empty(), "trailing junk refused");
		s = scan("select 5$1");
		expect(!s.error.empty(), "parameter right after a number refused");
		s = scan("select $0");
		expect(s.sqlstate == "42P02", "$0");
		s = scan("select $65536");
		expect(s.sqlstate == "42P02", "$65536");
		s = scan("select 1; select 2");
		expect(s.error.empty() && s.statements == 2, "two statements counted");
		s = scan("create rule r as on insert to t do also (insert into u values (1); insert into u values (2));");
		expect(s.error.empty() && s.statements == 1, "; inside parentheses");
		s = scan("  -- nothing\n ; ");
		expect(s.error.empty() && s.statements == 0, "empty");
		s = scan("select 'abc");
		expect(!s.error.empty(), "unterminated string");
		s = scan("select /* /* */ $1");
		expect(!s.error.empty(), "unterminated nested comment");
		s = scan("select $q$ $1");
		expect(!s.error.empty(), "unterminated dollar quote");
		s = scan("select 'a\\' $1 '");
		expect(s.sqlstate == "0A000", "backslash-quote: reads differently with standard_conforming_strings on and off");
		s = scan("select * from pg_namespace where nspname not like 'pg\\_%' and oid = $1");
		expect(s.error.empty() && s.params.size() == 1, "backslash without a quote after it is fine");
		s = scan("select 1E'\\' $1'");
		expect(s.error.empty() && s.params.empty(), "1E'...' is a number then an E string");
	}

	// ---- substitute
	{
		const std::string q = "select * from t where a = $1 and b = $2 and c = $1";
		Scan s = scan(q);
		std::vector<Value> vals(2);
		vals[0].text = "O'Brien";
		vals[1].null = true;
		expect(substitute(q, s.params, vals, {0, 23}) == "select * from t where a = 'O''Brien' and b = (NULL::int4) and c = 'O''Brien'", "substitute");
		const std::string q2 = "select 'a'$1, $1'b', $$x$$$1";
		s = scan(q2);
		vals.assign(1, Value());
		vals[0].text = "v";
		expect(substitute(q2, s.params, vals, {0}) == "select 'a' 'v', 'v' 'b', $$x$$ 'v'", "a literal never runs into a quote next to it");
	}

	// ---- psycopg 3: unnamed statement, text parameters
	{
		Extended x;
		expect(send(x, 'P', Parse("", "select name from t where id = $1 and n = $2", {23, 0})) == Extended::Wait, "P waits");
		send(x, 'B', Bind("", "", {{false, "7"}, {false, "it's"}}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run, "S runs");
		expect(x.sql() == "select name from t where id = ('7'::int4) and n = 'it''s'", "sql: " + x.sql());
		expect(x.takeAnswer() == message('1') + message('2'), "ParseComplete, BindComplete first");
		expect(x.running(), "running");
		expect(x.onRowDescription(T) == T, "Describe portal: the row description");
		expect(x.onComplete(C_SELECT) == C_SELECT, "CommandComplete");
		expect(x.onReady(Z) == Z, "ReadyForQuery");
		expect(!x.running(), "done");
	}
	// An INSERT: NoData for the Describe.
	{
		Extended x;
		send(x, 'P', Parse("", "insert into t values ($1)"));
		send(x, 'B', Bind("", "", {{true, ""}}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run && x.sql() == "insert into t values (NULL)", "insert sql");
		x.takeAnswer();
		expect(x.onComplete(C_INSERT) == message('n') + C_INSERT, "NoData then CommandComplete");
		expect(x.onReady(Z) == Z, "ready");
	}
	// No Describe: no row description goes out.
	{
		Extended x;
		send(x, 'P', Parse("", "select 1"));
		send(x, 'B', Bind("", "", {}));
		send(x, 'E', Execute(""));
		send(x, 'S');
		x.takeAnswer();
		expect(x.onRowDescription(T).empty(), "row description held back");
		expect(x.onComplete(C_SELECT) == C_SELECT && x.onReady(Z) == Z, "rest");
	}
	// psycopg's prepared statements (prepare_threshold): Parse+Sync, later Bind/Describe/Execute.
	{
		Extended x;
		send(x, 'P', Parse("_pg3_0", "select $1::text", {0}));
		expect(send(x, 'S') == Extended::Answer && x.wantsReady(), "Parse+Sync answered here");
		expect(x.takeAnswer() == message('1'), "ParseComplete");
		send(x, 'B', Bind("", "_pg3_0", {{false, "a"}}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run && x.sql() == "select 'a'::text", "named statement runs: " + x.sql());
		x.takeAnswer();
		x.onRowDescription(T);
		x.onComplete(C_SELECT);
		x.onReady(Z);
		send(x, 'P', Parse("_pg3_0", "select 2"));
		expect(send(x, 'S') == Extended::Answer && isError(x.takeAnswer(), "42P05"), "same name twice: 42P05");
		expect(x.deallocate(std::string("DEALLOCATE _pg3_0") + '\0'), "DEALLOCATE of ours answered here");
		expect(!x.deallocate("DEALLOCATE _pg3_0"), "now gone");
		send(x, 'P', Parse("_pg3_1", "select 1"));
		send(x, 'S');
		x.takeAnswer();
		expect(x.deallocate("deallocate prepare \"_pg3_1\" ;"), "DEALLOCATE PREPARE \"name\"");
		send(x, 'P', Parse("Mixed", "select 1"));
		send(x, 'S');
		x.takeAnswer();
		expect(!x.deallocate("DEALLOCATE Mixed"), "unquoted names fold to lower case");
		expect(x.deallocate("DEALLOCATE \"Mixed\""), "quoted keeps case");
		send(x, 'P', Parse("a", "select 1"));
		send(x, 'S');
		x.takeAnswer();
		expect(!x.deallocate("DISCARD ALL;"), "DISCARD ALL goes to the server");
		expect(!x.deallocate("DEALLOCATE a"), "and forgot ours");
		expect(!x.deallocate("DEALLOCATE other"), "not ours: to the server");
	}
	// Describe statement then Execute (pgjdbc): ParameterDescription, the row description, then BindComplete.
	{
		Extended x;
		send(x, 'P', Parse("S_1", "select * from t where id = $1", {23}));
		send(x, 'D', Describe('S', "S_1"));
		send(x, 'B', Bind("", "S_1", {{false, "1"}}));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run, "runs");
		expect(x.takeAnswer() == message('1'), "ParseComplete");
		std::string t;
		put16(t, 1);
		put32(t, 23);
		const std::string a = x.onRowDescription(T);
		expect(a == message('t', t) + T + message('2'), "t, T, then BindComplete: " + show(a));
	}
	// Describe without its Execute: refused, not guessed.
	{
		Extended x;
		send(x, 'P', Parse("s", "select 1"));
		send(x, 'D', Describe('S', "s"));
		expect(send(x, 'S') == Extended::Answer, "nothing to run");
		const std::string a = x.takeAnswer();
		expect(a.substr(0, 5) == message('1') && isError(a.substr(5), "0A000"), "ParseComplete then 0A000: " + show(a));
	}
	// Errors: the message, then everything up to Sync skipped, and nothing of that Sync runs.
	{
		Extended x;
		send(x, 'B', Bind("", "nope", {}));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Answer, "unknown statement: answered");
		expect(isError(x.takeAnswer(), "26000"), "26000");
		send(x, 'P', Parse("", "select $1"));
		send(x, 'B', Bind("", "", {{false, "1"}}, {1}));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "0A000"), "binary parameter refused");
		send(x, 'P', Parse("", "select $1"));
		send(x, 'B', Bind("", "", {{false, "1"}}, {}, {1}));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "0A000"), "binary result refused");
		send(x, 'P', Parse("", "select $1, $2"));
		send(x, 'B', Bind("", "", {{false, "1"}}));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "08P01"), "parameter count");
		send(x, 'P', Parse("", "select $1"));
		send(x, 'B', Bind("", "", {{false, std::string("a\0b", 3)}}));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "22021"), "zero byte refused");
		send(x, 'P', Parse("", "select 1; select 2"));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "42601"), "two statements refused");
		send(x, 'E', Execute("nope"));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "34000"), "unknown portal");
		send(x, 'P', std::string("x\0sel", 5));
		send(x, 'S');
		expect(isError(x.takeAnswer(), "08P01"), "truncated message");
		// An error after an Execute: that Execute does not run either.
		send(x, 'P', Parse("", "insert into t values (1)"));
		send(x, 'B', Bind("", "", {}));
		send(x, 'E', Execute(""));
		send(x, 'B', Bind("", "nope", {}));
		send(x, 'P', Parse("", "select 1"));
		expect(send(x, 'S') == Extended::Answer, "nothing runs");
		const std::string a = x.takeAnswer();
		expect(a.substr(0, 10) == message('1') + message('2') && isError(a.substr(10), "26000") && a.size() < 80, "1, 2, error: " + show(a));
		// And after the Sync all is well again.
		send(x, 'P', Parse("", "select 1"));
		send(x, 'B', Bind("", "", {}));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Run, "recovered");
	}
	// The backend's error: the answers before it, the error, then only ReadyForQuery.
	{
		Extended x;
		send(x, 'P', Parse("", "select * from nosuch where a = $1"));
		send(x, 'B', Bind("", "", {{false, "1"}}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		send(x, 'C', Close('S', ""));
		send(x, 'S');
		expect(x.takeAnswer() == message('1') + message('2'), "first");
		expect(x.onError(E) == E, "error");
		expect(x.onReady(Z) == Z, "then ReadyForQuery, not CloseComplete");
	}
	// Several Executes in one Sync (pgjdbc batches, psycopg pipelines): one query, answers in order.
	{
		Extended x;
		send(x, 'P', Parse("", "insert into t values ($1) -- one"));
		send(x, 'B', Bind("", "", {{false, "1"}}));
		send(x, 'E', Execute(""));
		send(x, 'B', Bind("", "", {{false, "2"}}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		send(x, 'C', Close('S', ""));
		expect(send(x, 'S') == Extended::Run, "runs");
		expect(x.sql() == "insert into t values ('1') -- one\n;\ninsert into t values ('2') -- one", "joined: " + x.sql());
		expect(x.takeAnswer() == message('1') + message('2'), "first");
		expect(x.onComplete(C_INSERT) == C_INSERT + message('2'), "first result, then the second Bind");
		expect(x.onComplete(C_INSERT) == message('n') + C_INSERT + message('3'), "second: NoData, result, CloseComplete");
		expect(x.onReady(Z) == Z, "ready");
	}
	// The empty statement: EmptyQueryResponse, no backend.
	{
		Extended x;
		send(x, 'P', Parse("", ""));
		send(x, 'B', Bind("", "", {}));
		send(x, 'D', Describe('P', ""));
		send(x, 'E', Execute(""));
		expect(send(x, 'S') == Extended::Answer, "answered here");
		expect(x.takeAnswer() == message('1') + message('2') + message('n') + message('I'), "1 2 n I");
	}
	// Flush: answers what it can; an Execute pending runs then, without ReadyForQuery.
	{
		Extended x;
		send(x, 'P', Parse("s", "select 1"));
		expect(send(x, 'H') == Extended::Answer && !x.wantsReady() && x.takeAnswer() == message('1'), "Flush: ParseComplete now");
		send(x, 'B', Bind("", "s", {}));
		send(x, 'E', Execute(""));
		expect(send(x, 'H', "", true) == Extended::Wait, "Flush with more queued: wait for it");
		expect(send(x, 'H') == Extended::Run && !x.wantsReady(), "Flush runs the Execute");
		expect(x.takeAnswer() == message('2'), "BindComplete");
		x.onRowDescription(T);
		expect(x.onComplete(C_SELECT) == C_SELECT, "result");
		expect(x.onReady(Z).empty(), "no ReadyForQuery for a Flush");
		expect(send(x, 'S') == Extended::Answer && x.wantsReady() && x.takeAnswer().empty(), "the Sync: just ReadyForQuery");
	}
	// Close answers CloseComplete and forgets.
	{
		Extended x;
		send(x, 'P', Parse("s", "select 1"));
		send(x, 'C', Close('S', "s"));
		send(x, 'B', Bind("", "s", {}));
		send(x, 'S');
		const std::string a = x.takeAnswer();
		expect(a.substr(0, 10) == message('1') + message('3') && isError(a.substr(10), "26000"), "closed: " + show(a));
	}

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("authnull_pg_extended_test: all passed\n");
	return 0;
}
