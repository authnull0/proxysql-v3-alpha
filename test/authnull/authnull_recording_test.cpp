// Standalone test for include/authnull_recording.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_recording_test.cpp -o /tmp/authnull_recording_test && /tmp/authnull_recording_test
//
// Session recording (authnull-service docs/DB-SESSION-RECORDING.md): a session whose policy says
// record has every statement written to a local spool -- its text with secrets masked, whether it
// was allowed, rows, duration, error; never result data -- which the database agent ships.
#include "authnull_recording.h"

#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <initializer_list>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static int failures = 0;
static void expect(bool ok, const std::string& what) {
	if (!ok) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}
static void masks(const std::string& in, const std::string& want) {
	std::string got = authnullMaskSecrets(in);
	if (got != want) {
		std::fprintf(stderr, "FAIL mask\n  in:   %s\n  got:  %s\n  want: %s\n", in.c_str(), got.c_str(), want.c_str());
		failures++;
	}
}

static std::vector<std::string> files(const std::string& dir) {
	std::vector<std::string> out;
	DIR* d = opendir(dir.c_str());
	if (!d) return out;
	while (struct dirent* e = readdir(d)) {
		std::string n = e->d_name;
		if (n != "." && n != "..") out.push_back(n);
	}
	closedir(d);
	return out;
}

static std::string slurp(const std::string& path) {
	std::ifstream f(path);
	std::stringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

int main() {
	// --- secrets are masked; everything else is as typed ---
	masks("ALTER ROLE app PASSWORD 'S3cret!'", "ALTER ROLE app PASSWORD '***'");
	masks("alter user app with password 'a''b'", "alter user app with password '***'");
	masks("CREATE USER u IDENTIFIED BY 'pw'", "CREATE USER u IDENTIFIED BY '***'");
	masks("SET PASSWORD FOR u = 'x'", "SET PASSWORD FOR u = '***'");
	masks("SET PASSWORD = PASSWORD('x')", "SET PASSWORD = PASSWORD('***')");
	masks("ALTER ROLE app PASSWORD $$dollar$$", "ALTER ROLE app PASSWORD '***'");
	masks("ALTER ROLE app PASSWORD $q$tag$q$ VALID UNTIL 'infinity'", "ALTER ROLE app PASSWORD '***' VALID UNTIL 'infinity'");
	masks("select * from users where password = 'x' and name = 'bob'", "select * from users where password = '***' and name = 'bob'");
	masks("select 'password' as p, 'PASSWORD ''x''' from t", "select 'password' as p, 'PASSWORD ''x''' from t");
	masks("select \"password\" from t", "select \"password\" from t");
	masks("-- password 'x'\nselect 1", "-- password 'x'\nselect 1");
	masks("select passwords from t where x = 'y'", "select passwords from t where x = 'y'");
	masks("insert into t values (1, 'a')", "insert into t values (1, 'a')");
	masks("ALTER ROLE app PASSWORD 'unterminated", "ALTER ROLE app PASSWORD '***'");
	// Bounded.
	std::string big = "select '" + std::string(10000, 'x') + "'";
	std::string m = authnullMaskSecrets(big);
	expect(m.size() <= kAuthnullRecordMaxStatement + 3 && m.substr(m.size() - 3) == "...", "a long statement is cut");

	// --- MySQL error messages quote values; recordings keep the message, not the values ---
	expect(authnullMaskErrorValues("[1062] Duplicate entry 'jane@acme.com' for key 'users.email'") ==
		"[1062] Duplicate entry '***' for key '***'", "duplicate entry masked");
	expect(authnullMaskErrorValues("[1406] Data too long for column 'note' at row 1") == "[1406] Data too long for column '***' at row 1",
		"column name masked too");
	expect(authnullMaskErrorValues("[1146] Table shop.nosuch doesn't exist") == "[1146] Table shop.nosuch doesn't exist",
		"an apostrophe inside a word is not a quote");
	expect(authnullMaskErrorValues("[1064] near 'it''s' at line 1") == "[1064] near '***' at line 1", "doubled quote inside a value");
	expect(authnullMaskErrorValues("[1366] Incorrect integer value: 'abc' for column 'n'") == "[1366] Incorrect integer value: '***' for column '***'",
		"several values");
	expect(authnullMaskErrorValues("[1105] unterminated 'secret") == "[1105] unterminated '***'", "unterminated");

	// --- one JSON line per statement ---
	AuthnullRecordedStatement st;
	st.session_id = 195; st.at_ms = 1794296684123; st.duration_ms = 12; st.user = "dbmfa_writer"; st.database = "dbmfa_test";
	st.client = "172.18.0.11:41148"; st.statement = "ALTER ROLE x PASSWORD 'p'"; st.allowed = true; st.rows = 3; st.affected = 1; st.hostgroup = 6;
	std::string line = authnullRecordLine(st);
	auto j = nlohmann::json::parse(line);
	expect(j["sid"] == 195 && j["at"] == 1794296684123LL && j["durMs"] == 12 && j["user"] == "dbmfa_writer" && j["db"] == "dbmfa_test" &&
		j["client"] == "172.18.0.11:41148" && j["allowed"] == true && j["rows"] == 3 && j["affected"] == 1 && j["hg"] == 6, "record fields: " + line);
	expect(j["stmt"] == "ALTER ROLE x PASSWORD '***'", "the line's statement is masked");
	expect(line.find('\n') == std::string::npos, "one line");
	st.allowed = false; st.error = "Access denied: Query not permitted for this user";
	j = nlohmann::json::parse(authnullRecordLine(st));
	expect(j["allowed"] == false && j["error"] == "Access denied: Query not permitted for this user", "a refused statement");

	// --- the policy opts in: credentialSubject.session.record ---
	expect(authnullRecordFromJSON(nlohmann::json::parse(R"({"session":{"record":true}})")), "record: true");
	expect(authnullRecordFromJSON(nlohmann::json::parse(R"({"session":{"record":true,"endsAt":1794312000}})")), "record with limits");
	expect(!authnullRecordFromJSON(nlohmann::json::parse(R"({"session":{"record":false}})")), "record: false");
	expect(!authnullRecordFromJSON(nlohmann::json::parse(R"({"session":{"record":"true"}})")), "only a boolean");
	expect(!authnullRecordFromJSON(nlohmann::json::parse(R"({"session":{"maxDurationMinutes":5}})")), "not asked");
	expect(!authnullRecordFromJSON(nlohmann::json::parse(R"({"databaseName":"d"})")), "no session block");
	expect(!authnullRecordFromJSON(nlohmann::json::parse(R"([1])")), "not an object");

	// --- the spool: one file per 5-second bucket, private ---
	char tmpl[] = "/tmp/authnull_rec_XXXXXX";
	std::string base = mkdtemp(tmpl);
	std::string dir = base + "/spool";
	long long now = 1794296680;
	AuthnullRecorder rec(dir, [&now]() { return now; });
	expect(rec.append("{\"a\":1}"), "append");
	now += 2;
	expect(rec.append("{\"a\":2}"), "append, same bucket");
	now += 4; // 1794296686: the next bucket
	expect(rec.append("{\"a\":3}"), "append, next bucket");
	auto fs = files(dir);
	expect(fs.size() == 2, "two buckets, two files");
	expect(slurp(dir + "/1794296680.jsonl") == "{\"a\":1}\n{\"a\":2}\n", "first bucket's lines");
	expect(slurp(dir + "/1794296685.jsonl") == "{\"a\":3}\n", "second bucket's line");
	struct stat sd, sf;
	stat(dir.c_str(), &sd);
	stat((dir + "/1794296680.jsonl").c_str(), &sf);
	expect((sd.st_mode & 0777) == 0700 && (sf.st_mode & 0777) == 0600, "private directory and files");

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
