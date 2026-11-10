// Standalone guard: no AuthNull code prints result rows or query text to ProxySQL's log.
// Run from the repository root; no ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra test/authnull/authnull_no_data_in_logs_test.cpp -o /tmp/nolog && /tmp/nolog
//
// ProxySQL's stdout is its log (/var/lib/proxysql/proxysql.log). get_resultset printed every row
// it sent over the MySQL protocol -- which includes the admin interface, so the agent's read of
// pgsql_users put every managed role's password in the log in clear, alongside customers' query
// results -- and both session classes printed every query's full text. The proof that they are
// gone is a ProxySQL build whose log stays clean (checked on the lab); this keeps them from coming
// back unnoticed.
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static int failures = 0;

static std::string slurp(const std::string& path) {
	std::ifstream f(path);
	if (!f) {
		std::fprintf(stderr, "FAIL cannot read %s (run from the repository root)\n", path.c_str());
		failures++;
		return "";
	}
	std::stringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

// A line that writes to stdout and names one of the things that must not reach the log.
static void forbid(const std::string& path, const std::vector<std::string>& needles) {
	std::istringstream lines(slurp(path));
	std::string line;
	int n = 0;
	while (std::getline(lines, line)) {
		n++;
		if (line.find("std::cout") == std::string::npos && line.find("printf(") == std::string::npos &&
			line.find("syslog(") == std::string::npos) continue;
		for (const auto& needle : needles) {
			if (line.find(needle) != std::string::npos) {
				std::fprintf(stderr, "FAIL %s:%d prints %s: %s\n", path.c_str(), n, needle.c_str(), line.c_str());
				failures++;
			}
		}
	}
}

int main() {
	// Result sets: the rows, as sent.
	forbid("lib/MySQL_ResultSet.cpp", {"packet_data", "[DEBUG] Row", "Result Set Before Sending"});
	// PgSQL result sets: copy_row_to_PgSQL_Query_Result wrote every row it sent to syslog.
	forbid("lib/PgSQL_Protocol.cpp", {"ROW[", "row_data", "PQgetvalue", "data='%.*s'"});
	// Sessions: the query text.
	// syslog too: the query text belongs in a session recording, masked, only when the policy asks
	// for one (authnull_recording.h), never in the system log.
	forbid("lib/MySQL_Session.cpp", {"Parsing query", "<< query", "<< q <<", "query.c_str()", "Query Executed"});
	forbid("lib/PgSQL_Session.cpp", {"Parsing query", "<< query", "<< q <<", "query.c_str()", "Query Executed"});

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
