#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

//#define __CLASS_STANDARD_MYSQL_THREAD_H

#include <functional>
#include <vector>

#include "PgSQL_HostGroups_Manager.h"
#include "prometheus_helpers.h"
#define PGSQL_THREAD_IMPLEMENTATION
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Thread.h"
#include <dirent.h>
#include <libgen.h>
#include "re2/re2.h"
#include "re2/regexp.h"

#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "StatCounters.h"
#include "MySQL_PreparedStatement.h"
#include "PgSQL_Logger.hpp"

#include <fcntl.h>

using std::vector;
using std::function;

#ifdef DEBUG
static PgSQL_Session* sess_stopat;
#endif

#ifdef epoll_create1
#define EPOLL_CREATE epoll_create1(0)
#else
#define EPOLL_CREATE epoll_create(1)
#endif

#define PROXYSQL_LISTEN_LEN 1024
#define MIN_THREADS_FOR_MAINTENANCE 8

extern PgSQL_Query_Processor* GloPgQPro;
extern PgSQL_Threads_Handler* GloPTH;
extern MySQL_Monitor* GloMyMon;
extern PgSQL_Monitor* GloPgMon;
extern PgSQL_Logger* GloPgSQL_Logger;

typedef struct mythr_st_vars {
	enum PgSQL_Thread_status_variable v_idx;
	p_th_counter::metric m_idx;
	char* name;
	uint32_t conv;
} mythr_st_vars_t;

typedef struct mythr_g_st_vars {
	enum PgSQL_Thread_status_variable v_idx;
	p_th_gauge::metric m_idx;
	char* name;
	uint32_t conv;
} mythr_g_st_vars_t;

// Note: the order here is not important. 
mythr_st_vars_t PgSQL_Thread_status_variables_counter_array[]{
	/*{st_var_backend_stmt_prepare, p_th_counter::com_backend_stmt_prepare, (char*)"Com_backend_stmt_prepare"},
	{ st_var_backend_stmt_execute, p_th_counter::com_backend_stmt_execute, (char*)"Com_backend_stmt_execute" },
	{ st_var_backend_stmt_close,   p_th_counter::com_backend_stmt_close,   (char*)"Com_backend_stmt_close" },
	{ st_var_frontend_stmt_prepare, p_th_counter::com_frontend_stmt_prepare, (char*)"Com_frontend_stmt_prepare" },
	{ st_var_frontend_stmt_execute, p_th_counter::com_frontend_stmt_execute, (char*)"Com_frontend_stmt_execute" },
	{ st_var_frontend_stmt_close,   p_th_counter::com_frontend_stmt_close,   (char*)"Com_frontend_stmt_close" },
	{ st_var_queries,               p_th_counter::questions,               (char*)"Questions" },
	{ st_var_queries_slow,          p_th_counter::slow_queries,            (char*)"Slow_queries" },
	{ st_var_queries_gtid,          p_th_counter::gtid_consistent_queries, (char*)"GTID_consistent_queries" },
	{ st_var_gtid_session_collected,p_th_counter::gtid_session_collected,  (char*)"GTID_session_collected" },
	{ st_var_queries_backends_bytes_recv,  p_th_counter::queries_backends_bytes_recv,  (char*)"Queries_backends_bytes_recv" },
	{ st_var_queries_backends_bytes_sent,  p_th_counter::queries_backends_bytes_sent,  (char*)"Queries_backends_bytes_sent" },
	{ st_var_queries_frontends_bytes_recv, p_th_counter::queries_frontends_bytes_recv, (char*)"Queries_frontends_bytes_recv" },
	{ st_var_queries_frontends_bytes_sent, p_th_counter::queries_frontends_bytes_sent, (char*)"Queries_frontends_bytes_sent" },
	{ st_var_query_processor_time , p_th_counter::query_processor_time_nsec,  (char*)"Query_Processor_time_nsec", 1000 * 1000 * 1000 },
	{ st_var_backend_query_time ,   p_th_counter::backend_query_time_nsec,  (char*)"Backend_query_time_nsec", 1000 * 1000 * 1000 },
	{ st_var_ConnPool_get_conn_latency_awareness , p_th_counter::connpool_get_conn_latency_awareness, (char*)"ConnPool_get_conn_latency_awareness" },
	{ st_var_ConnPool_get_conn_immediate, p_th_counter::connpool_get_conn_immediate,      (char*)"ConnPool_get_conn_immediate" },
	{ st_var_ConnPool_get_conn_success,   p_th_counter::connpool_get_conn_success,        (char*)"ConnPool_get_conn_success" },
	{ st_var_ConnPool_get_conn_failure,   p_th_counter::connpool_get_conn_failure,        (char*)"ConnPool_get_conn_failure" },
	{ st_var_killed_connections,          p_th_counter::mysql_killed_backend_connections, (char*)"mysql_killed_backend_connections" },
	{ st_var_killed_queries,              p_th_counter::mysql_killed_backend_queries,     (char*)"mysql_killed_backend_queries" },
	{ st_var_hostgroup_locked_set_cmds,   p_th_counter::hostgroup_locked_set_cmds,        (char*)"hostgroup_locked_set_cmds" },
	{ st_var_hostgroup_locked_queries,    p_th_counter::hostgroup_locked_queries,         (char*)"hostgroup_locked_queries" },
	{ st_var_unexpected_com_quit,         p_th_counter::mysql_unexpected_frontend_com_quit,(char*)"mysql_unexpected_frontend_com_quit" },
	{ st_var_unexpected_packet,           p_th_counter::mysql_unexpected_frontend_packets,(char*)"mysql_unexpected_frontend_packets" },
	{ st_var_queries_with_max_lag_ms__total_wait_time_us , p_th_counter::queries_with_max_lag_ms__total_wait_time_us,  (char*)"queries_with_max_lag_ms__total_wait_time_us" },
	{ st_var_queries_with_max_lag_ms__delayed , p_th_counter::queries_with_max_lag_ms__delayed,  (char*)"queries_with_max_lag_ms__delayed" },
	{ st_var_queries_with_max_lag_ms,     p_th_counter::queries_with_max_lag_ms,          (char*)"queries_with_max_lag_ms" },
	{ st_var_backend_lagging_during_query,p_th_counter::backend_lagging_during_query,     (char*)"backend_lagging_during_query" },
	{ st_var_backend_offline_during_query,p_th_counter::backend_offline_during_query,     (char*)"backend_offline_during_query" },
	{ st_var_aws_aurora_replicas_skipped_during_query , p_th_counter::aws_aurora_replicas_skipped_during_query,  (char*)"get_aws_aurora_replicas_skipped_during_query" },
	{ st_var_automatic_detected_sqli,     p_th_counter::automatic_detected_sql_injection,  (char*)"automatic_detected_sql_injection" },
	{ st_var_mysql_whitelisted_sqli_fingerprint,p_th_counter::mysql_whitelisted_sqli_fingerprint,     (char*)"mysql_whitelisted_sqli_fingerprint" },
	{ st_var_max_connect_timeout_err,     p_th_counter::max_connect_timeouts,             (char*)"max_connect_timeouts" },
	{ st_var_generated_pkt_err,           p_th_counter::generated_error_packets,          (char*)"generated_error_packets" },
	{ st_var_client_host_error_killed_connections, p_th_counter::client_host_error_killed_connections, (char*)"client_host_error_killed_connections" },*/
};

mythr_g_st_vars_t PgSQL_Thread_status_variables_gauge_array[]{
	/*{st_var_hostgroup_locked,            p_th_gauge::client_connections_hostgroup_locked,  (char*)"Client_Connections_hostgroup_locked"}*/
};

extern mysql_variable_st mysql_tracked_variables[];

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef __cplusplus
}
#endif /* __cplusplus */


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_THREAD_VERSION "0.2.0902" DEB


#define DEFAULT_NUM_THREADS	4
#define DEFAULT_STACK_SIZE	1024*1024

#define SESSIONS_FOR_CONNECTIONS_HANDLER	64

__thread unsigned int __thread_PgSQL_Thread_Variables_version;

volatile static unsigned int __global_PgSQL_Thread_Variables_version;


PgSQL_Listeners_Manager::PgSQL_Listeners_Manager() {
	ifaces = new PtrArray();
}
PgSQL_Listeners_Manager::~PgSQL_Listeners_Manager() {
	while (ifaces->len) {
		iface_info* ifi = (iface_info*)ifaces->remove_index_fast(0);
		shutdown(ifi->fd, SHUT_RDWR);
		close(ifi->fd);
		if (ifi->port == 0) {
			unlink(ifi->address);
		}
		delete ifi;
	}
	delete ifaces;
	ifaces = NULL;
}

int PgSQL_Listeners_Manager::add(const char* iface, unsigned int num_threads, int** perthrsocks) {
	for (unsigned int i = 0; i < ifaces->len; i++) {
		iface_info* ifi = (iface_info*)ifaces->index(i);
		if (strcmp(ifi->iface, iface) == 0) {
			return -1;
		}
	}

	char* address = NULL; char* port = NULL;
	int s = -1;
	char* h = NULL;
	bool is_ipv6 = false;

	if (*(char*)iface == '[') {
		is_ipv6 = true;
		char* p = strchr((char*)iface, ']');
		if (p == NULL) {
			proxy_error("Invalid IPv6 address: %s\n", iface);
			return -1;
		}
		h = (char*)++iface; // remove first '['
		*p = '\0';
		iface = p++; // remove last ']'
		address = h;
		port = ++p; // remove ':'
	}
	else {
		c_split_2(iface, ":", &address, &port);
	}

#ifdef SO_REUSEPORT
	if (GloVars.global.reuseport == false) {
		s = (atoi(port) ? listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN) : listen_on_unix(address, PROXYSQL_LISTEN_LEN));
	}
	else {
		if (atoi(port) == 0) {
			s = listen_on_unix(address, PROXYSQL_LISTEN_LEN);
		}
		else {
			// for TCP we will use SO_REUSEPORT
			int* l_perthrsocks = (int*)malloc(sizeof(int) * num_threads);
			unsigned int i;
			for (i = 0; i < num_threads; i++) {
				s = listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN, true);
				ioctl_FIONBIO(s, 1);
				iface_info* ifi = new iface_info((char*)iface, address, atoi(port), s);
				ifaces->add(ifi);
				l_perthrsocks[i] = s;
			}
			*perthrsocks = l_perthrsocks;
			s = 0;
		}
	}
#else
	s = (atoi(port) ? listen_on_port(address, atoi(port), PROXYSQL_LISTEN_LEN) : listen_on_unix(address, PROXYSQL_LISTEN_LEN));
#endif /* SO_REUSEPORT */
	if (s == -1) {
		if (is_ipv6 == false) {
			free(address);
			free(port);
		}

		return s;
	}
	if (s > 0) {
		ioctl_FIONBIO(s, 1);
		iface_info* ifi = new iface_info((char*)iface, address, atoi(port), s);
		ifaces->add(ifi);
	}
	if (is_ipv6 == false) {
		free(address);
		free(port);
	}

	return s;
}

int PgSQL_Listeners_Manager::find_idx(const char* iface) {
	for (unsigned int i = 0; i < ifaces->len; i++) {
		iface_info* ifi = (iface_info*)ifaces->index(i);
		if (strcmp(ifi->iface, iface) == 0) {
			return i;
		}
	}
	return -1;
}

iface_info* PgSQL_Listeners_Manager::find_iface_from_fd(int fd) {
	for (unsigned int i = 0; i < ifaces->len; i++) {
		iface_info* ifi = (iface_info*)ifaces->index(i);
		if (ifi->fd == fd) {
			return ifi;
		}
	}
	return NULL;
}

int PgSQL_Listeners_Manager::find_idx(const char* address, int port) {
	for (unsigned int i = 0; i < ifaces->len; i++) {
		iface_info* ifi = (iface_info*)ifaces->index(i);
		if (strcmp(ifi->address, address) == 0 && ifi->port == port) {
			return i;
		}
	}
	return -1;
}

int PgSQL_Listeners_Manager::get_fd(unsigned int idx) {
	iface_info* ifi = (iface_info*)ifaces->index(idx);
	return ifi->fd;
}

void PgSQL_Listeners_Manager::del(unsigned int idx) {
	iface_info* ifi = (iface_info*)ifaces->remove_index_fast(idx);
	if (ifi->port == 0) {
		unlink(ifi->address);
	}
	delete ifi;
}

static char* pgsql_thread_variables_names[] = {
	(char*)"authentication_method",
	(char*)"shun_on_failures",
	(char*)"shun_recovery_time_sec",
	(char*)"unshun_algorithm",
	(char*)"query_retries_on_failure",
	(char*)"client_host_cache_size",
	(char*)"client_host_error_counts",
	(char*)"connect_retries_on_failure",
	(char*)"connect_retries_delay",
	(char*)"connection_delay_multiplex_ms",
	(char*)"connection_max_age_ms",
	(char*)"connect_timeout_client",
	(char*)"connect_timeout_server",
	(char*)"connect_timeout_server_max",
	(char*)"enable_client_deprecate_eof",
	(char*)"enable_server_deprecate_eof",
	(char*)"enable_load_data_local_infile",
	(char*)"eventslog_filename",
	(char*)"eventslog_filesize",
	(char*)"eventslog_default_log",
	(char*)"eventslog_format",
	(char*)"auditlog_filename",
	(char*)"auditlog_filesize",
	//(char *)"default_charset", // removed in 2.0.13 . Obsoleted previously using MySQL_Variables instead
	(char*)"handle_unknown_charset",
	(char*)"free_connections_pct",
	(char*)"connection_warming",
#ifdef IDLE_THREADS
	(char*)"session_idle_ms",
#endif // IDLE_THREADS
	(char*)"have_ssl",
	(char*)"have_compress",
	(char*)"interfaces",
	(char*)"log_mysql_warnings_enabled",
	(char*)"monitor_enabled",
	(char*)"monitor_history",
	(char*)"monitor_connect_interval",
	(char*)"monitor_connect_timeout",
	(char*)"monitor_ping_interval",
	(char*)"monitor_ping_max_failures",
	(char*)"monitor_ping_timeout",
/*
	(char*)"monitor_aws_rds_topology_discovery_interval",
	(char*)"monitor_read_only_interval",
	(char*)"monitor_read_only_timeout",
	(char*)"monitor_read_only_max_timeout_count",
	(char*)"monitor_replication_lag_group_by_host",
	(char*)"monitor_replication_lag_interval",
	(char*)"monitor_replication_lag_timeout",
	(char*)"monitor_replication_lag_count",
	(char*)"monitor_groupreplication_healthcheck_interval",
	(char*)"monitor_groupreplication_healthcheck_timeout",
	(char*)"monitor_groupreplication_healthcheck_max_timeout_count",
	(char*)"monitor_groupreplication_max_transactions_behind_count",
	(char*)"monitor_groupreplication_max_transactions_behind_for_read_only",
	(char*)"monitor_galera_healthcheck_interval",
	(char*)"monitor_galera_healthcheck_timeout",
	(char*)"monitor_galera_healthcheck_max_timeout_count",
*/
	(char*)"monitor_username",
	(char*)"monitor_password",
/*
	(char*)"monitor_replication_lag_use_percona_heartbeat",
	(char*)"monitor_query_interval",
	(char*)"monitor_query_timeout",
	(char*)"monitor_slave_lag_when_null",
*/
	(char*)"monitor_threads",
/*
	(char*)"monitor_threads_min",
	(char*)"monitor_threads_max",
	(char*)"monitor_threads_queue_maxsize",
	(char*)"monitor_local_dns_cache_ttl",
	(char*)"monitor_local_dns_cache_refresh_interval",
	(char*)"monitor_local_dns_resolver_queue_maxsize",
	(char*)"monitor_wait_timeout",
	(char*)"monitor_writer_is_also_reader",
*/
	(char*)"max_allowed_packet",
	(char*)"tcp_keepalive_time",
	(char*)"use_tcp_keepalive",
	(char*)"automatic_detect_sqli",
	(char*)"firewall_whitelist_enabled",
	(char*)"firewall_whitelist_errormsg",
	(char*)"throttle_connections_per_sec_to_hostgroup",
	(char*)"max_transaction_idle_time",
	(char*)"max_transaction_time",
	(char*)"multiplexing",
	(char*)"log_unhealthy_connections",
	(char*)"enforce_autocommit_on_reads",
	(char*)"autocommit_false_not_reusable",
	(char*)"autocommit_false_is_transaction",
	(char*)"verbose_query_error",
	(char*)"hostgroup_manager_verbose",
	(char*)"binlog_reader_connect_retry_msec",
	(char*)"threshold_query_length",
	(char*)"threshold_resultset_size",
	(char*)"query_digests_max_digest_length",
	(char*)"query_digests_max_query_length",
	(char*)"query_digests_grouping_limit",
	(char*)"query_digests_groups_grouping_limit",
	(char*)"query_rules_fast_routing_algorithm",
	(char*)"wait_timeout",
	(char*)"throttle_max_bytes_per_second_to_client",
	(char*)"throttle_ratio_server_to_client",
	(char*)"max_connections",
	(char*)"max_stmts_per_connection",
	(char*)"max_stmts_cache",
	(char*)"mirror_max_concurrency",
	(char*)"mirror_max_queue_length",
	(char*)"default_max_latency_ms",
	(char*)"default_query_delay",
	(char*)"default_query_timeout",
	(char*)"query_processor_iterations",
	(char*)"query_processor_regex",
	(char*)"set_query_lock_on_hostgroup",
	(char*)"set_parser_algorithm",
	(char*)"auto_increment_delay_multiplex",
	(char*)"auto_increment_delay_multiplex_timeout_ms",
	(char*)"long_query_time",
	(char*)"query_cache_size_MB",
	(char*)"query_cache_soft_ttl_pct",
	(char*)"query_cache_handle_warnings",
	(char*)"ping_interval_server_msec",
	(char*)"ping_timeout_server",
	(char*)"default_schema",
	(char*)"poll_timeout",
	(char*)"poll_timeout_on_failure",
	(char*)"server_capabilities",
	(char*)"server_version",
	(char*)"default_client_encoding",
	(char*)"keep_multiplexing_variables",
	(char*)"kill_backend_connection_when_disconnect",
	(char*)"client_session_track_gtid",
	(char*)"sessions_sort",
#ifdef IDLE_THREADS
	(char*)"session_idle_show_processlist",
#endif // IDLE_THREADS
	(char*)"show_processlist_extended",
	(char*)"commands_stats",
	(char*)"query_digests",
	(char*)"query_digests_lowercase",
	(char*)"query_digests_replace_null",
	(char*)"query_digests_no_digits",
	(char*)"query_digests_normalize_digest_text",
	(char*)"query_digests_track_hostname",
	(char*)"query_digests_keep_comment",
	(char*)"parse_failure_logs_digest",
	(char*)"servers_stats",
	(char*)"default_reconnect",
#ifdef DEBUG
	(char*)"session_debug",
#endif /* DEBUG */
	(char*)"ssl_p2s_ca",
	(char*)"ssl_p2s_capath",
	(char*)"ssl_p2s_cert",
	(char*)"ssl_p2s_key",
	(char*)"ssl_p2s_cipher",
	(char*)"ssl_p2s_crl",
	(char*)"ssl_p2s_crlpath",
	(char*)"stacksize",
	(char*)"threads",
	(char*)"init_connect",
	(char*)"ldap_user_variable",
	(char*)"add_ldap_user_comment",
	(char*)"default_session_track_gtids",
	(char*)"min_num_servers_lantency_awareness",
	(char*)"aurora_max_lag_ms_only_read_from_replicas",
	(char*)"stats_time_backend_query",
	(char*)"stats_time_query_processor",
	(char*)"query_cache_stores_empty_result",
	(char*)"data_packets_history_size",
	(char*)"handle_warnings",
	NULL
};

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using th_counter_tuple =
std::tuple<
	p_th_counter::metric,
	metric_name,
	metric_help,
	metric_tags
>;

using th_gauge_tuple =
std::tuple<
	p_th_gauge::metric,
	metric_name,
	metric_help,
	metric_tags
>;

using th_counter_vector = std::vector<th_counter_tuple>;
using th_gauge_vector = std::vector<th_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the PgSQL_Thread module.
 *
 * @note Many metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  separated using a line separator comment.
 */
const std::tuple<th_counter_vector, th_gauge_vector>
th_metrics_map = std::make_tuple(
	th_counter_vector{
		// ====================================================================
		std::make_tuple(
			p_th_counter::queries_backends_bytes_sent,
			"proxysql_queries_backends_bytes_total",
			"Total number of bytes (sent|received) in backend connections.",
			metric_tags {
				{ "traffic_flow", "sent" }
			}
		),
		std::make_tuple(
			p_th_counter::queries_backends_bytes_recv,
			"proxysql_queries_backends_bytes_total",
			"Total number of bytes (sent|received) in backend connections.",
			metric_tags {
				{ "traffic_flow", "received" }
			}
		),
	// ====================================================================

	// ====================================================================
	std::make_tuple(
		p_th_counter::queries_frontends_bytes_sent,
		"proxysql_queries_frontends_bytes_total",
		"Total number of bytes (sent|received) in frontend connections.",
		metric_tags {
			{ "traffic_flow", "sent" }
		}
	),
	std::make_tuple(
		p_th_counter::queries_frontends_bytes_recv,
		"proxysql_queries_frontends_bytes_total",
		"Total number of bytes (sent|received) in frontend connections.",
		metric_tags {
			{ "traffic_flow", "received" }
		}
	),
	// ====================================================================

	std::make_tuple(
		p_th_counter::query_processor_time_nsec,
		"proxysql_query_processor_time_seconds_total",
		"The time spent inside the \"Query Processor\" to determine what action needs to be taken with the query (internal module).",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::backend_query_time_nsec,
		"proxysql_backend_query_time_seconds_total",
		"Time spent making network calls to communicate with the backends.",
		metric_tags {}
	),

	// ====================================================================
	std::make_tuple(
		p_th_counter::com_backend_stmt_prepare,
		"proxysql_com_backend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by ProxySQL against the backends.",
		metric_tags {
			{ "op", "prepare" }
		}
	),
	std::make_tuple(
		p_th_counter::com_backend_stmt_execute,
		"proxysql_com_backend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by ProxySQL against the backends.",
		metric_tags {
			{ "op", "execute" }
		}
	),
	std::make_tuple(
		p_th_counter::com_backend_stmt_close,
		"proxysql_com_backend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by ProxySQL against the backends.",
		metric_tags {
			{ "op", "close" }
		}
	),
	// ====================================================================

	// ====================================================================
	std::make_tuple(
		p_th_counter::com_frontend_stmt_prepare,
		"proxysql_com_frontend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by clients.",
		metric_tags {
			{ "op", "prepare" }
		}
	),
	std::make_tuple(
		p_th_counter::com_frontend_stmt_execute,
		"proxysql_com_frontend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by clients.",
		metric_tags {
			{ "op", "execute" }
		}
	),
	std::make_tuple(
		p_th_counter::com_frontend_stmt_close,
		"proxysql_com_frontend_stmt_total",
		"Represents the number of statements (PREPARE|EXECUTE|CLOSE) executed by clients.",
		metric_tags {
			{ "op", "close" }
		}
	),
	// ====================================================================

	std::make_tuple(
		p_th_counter::questions,
		"proxysql_questions_total",
		"The total number of client requests / statements executed.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::slow_queries,
		"proxysql_slow_queries_total",
		"The total number of queries with an execution time greater than \"mysql-long_query_time\" milliseconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::gtid_consistent_queries,
		"proxysql_gtid_consistent_queries_total",
		"Total queries with GTID consistent read.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::gtid_session_collected,
		"proxysql_gtid_session_collected_total",
		"Total queries with GTID session state.",
		metric_tags {}
	),

	// ====================================================================
	std::make_tuple(
		p_th_counter::connpool_get_conn_latency_awareness,
		"proxysql_connpool_get_conn_success_latency_awareness_total",
		"The connection was picked using the latency awareness algorithm.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::connpool_get_conn_immediate,
		"proxysql_connpool_get_conn_success_immediate_total",
		"The connection is provided from per-thread cache.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::connpool_get_conn_success,
		"proxysql_connpool_get_conn_success_total",
		"The session is able to get a connection, either from per-thread cache or connection pool.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::connpool_get_conn_failure,
		"proxysql_connpool_get_conn_failure_total",
		"The connection pool cannot provide any connection.",
		metric_tags {}
	),
	// ====================================================================

	std::make_tuple(
		p_th_counter::generated_error_packets,
		"proxysql_generated_error_packets_total",
		"Total generated error packets.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::max_connect_timeouts,
		"proxysql_max_connect_timeouts_total",
		"Maximum connection timeout reached when trying to connect to backend sever.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::backend_lagging_during_query,
		"proxysql_backend_lagging_during_query_total",
		"Query failed because server was shunned due to lag.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::backend_offline_during_query,
		"proxysql_backend_offline_during_query_total",
		"Query failed because server was offline.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::queries_with_max_lag_ms,
		"proxysql_queries_with_max_lag_total",
		"Received queries that have a 'max_lag' attribute.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::queries_with_max_lag_ms__delayed,
		"proxysql_queries_with_max_lag__delayed_total",
		"Query delayed because no connection was selected due to 'max_lag' annotation.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::queries_with_max_lag_ms__total_wait_time_us,
		"proxysql_queries_with_max_lag__total_wait_time_total",
		"Total waited time due to connection selection because of 'max_lag' annotation.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::mysql_unexpected_frontend_com_quit,
		"proxysql_mysql_unexpected_frontend_com_quit_total",
		"Unexpected 'COM_QUIT' received from the client.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::hostgroup_locked_set_cmds,
		"proxysql_hostgroup_locked_set_cmds_total",
		"Total number of connections that have been locked in a hostgroup.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::hostgroup_locked_queries,
		"proxysql_hostgroup_locked_queries_total",
		"Query blocked because connection is locked into some hostgroup but is trying to reach other.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::mysql_unexpected_frontend_packets,
		"proxysql_mysql_unexpected_frontend_packets_total",
		"Unexpected packet received from client.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::aws_aurora_replicas_skipped_during_query,
		"proxysql_aws_aurora_replicas_skipped_during_query_total",
		"Replicas skipped due to current lag being higher than 'max_lag' annotation.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::automatic_detected_sql_injection,
		"proxysql_automatic_detected_sql_injection_total",
		"Blocked a detected 'sql injection' attempt.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::mysql_whitelisted_sqli_fingerprint,
		"proxysql_mysql_whitelisted_sqli_fingerprint_total",
		"Detected a whitelisted 'sql injection' fingerprint.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::mysql_killed_backend_connections,
		"proxysql_mysql_killed_backend_connections_total",
		"Number of backend connection killed.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::mysql_killed_backend_queries,
		"proxysql_mysql_killed_backend_queries_total",
		"Killed backend queries.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_counter::client_host_error_killed_connections,
		"proxysql_client_host_error_killed_connections",
		"Killed client connections because address exceeded 'client_host_error_counts'.",
		metric_tags {}
	)
	},
	th_gauge_vector{
		std::make_tuple(
			p_th_gauge::active_transactions,
			"proxysql_active_transactions",
			"Provides a count of how many client connection are currently processing a transaction.",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::client_connections_non_idle,
			"proxysql_client_connections_non_idle",
			"Number of client connections that are currently handled by the main worker threads.",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::client_connections_hostgroup_locked,
			"proxysql_client_connections_hostgroup_locked",
			"Number of client connection locked to a specific hostgroup.",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mysql_backend_buffers_bytes,
			"proxysql_mysql_backend_buffers_bytes",
			"Buffers related to backend connections if \"fast_forward\" is used (0 means fast_forward is not used).",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mysql_frontend_buffers_bytes,
			"proxysql_mysql_frontend_buffers_bytes",
			"Buffers related to frontend connections (read/write buffers and other queues).",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mysql_session_internal_bytes,
			"proxysql_mysql_session_internal_bytes",
			"Other memory used by ProxySQL to handle MySQL Sessions.",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mirror_concurrency,
			"proxysql_mirror_concurrency",
			"Mirror current concurrency",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mirror_queue_lengths,
			"proxysql_mirror_queue_lengths",
			"Mirror queue length",
			metric_tags {}
		),
		std::make_tuple(
			p_th_gauge::mysql_thread_workers,
			"proxysql_mysql_thread_workers",
			"Number of MySQL Thread workers i.e. 'mysql-threads'",
			metric_tags {}
		),
	// global_variables
	std::make_tuple(
		p_th_gauge::mysql_wait_timeout,
		"proxysql_mysql_wait_timeout",
		"If a proxy session has been idle for more than this threshold, the proxy will kill the session.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_max_connections,
		"proxysql_mysql_max_connections",
		"The maximum number of client connections that the proxy can handle.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_enabled,
		"proxysql_mysql_monitor_enabled",
		"Enables or disables MySQL Monitor.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_ping_interval,
		"proxysql_mysql_monitor_ping_interval",
		"How frequently a ping check is performed, in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_ping_timeout,
		"proxysql_mysql_monitor_ping_timeout_seconds",
		"Ping timeout in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_ping_max_failures,
		"proxysql_mysql_monitor_ping_max_failures",
		"Reached maximum ping attempts from monitor.",
		metric_tags {}
	),
	std::make_tuple (
		p_th_gauge::mysql_monitor_aws_rds_topology_discovery_interval,
		"proxysql_mysql_monitor_aws_rds_topology_discovery_interval",
		"How frequently a topology discovery is performed, e.g. a value of 500 means one topology discovery every 500 read-only checks ",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_read_only_interval,
		"proxysql_mysql_monitor_read_only_interval_seconds",
		"How frequently a read only check is performed, in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_read_only_timeout,
		"proxysql_mysql_monitor_read_only_timeout_seconds",
		"Read only check timeout in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_writer_is_also_reader,
		"proxysql_mysql_monitor_writer_is_also_reader",
		"Encodes different behaviors for nodes depending on their 'READ_ONLY' flag value.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_replication_lag_group_by_host,
		"proxysql_monitor_replication_lag_group_by_host",
		"Encodes different replication lag check if the same server is in multiple hostgroups.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_replication_lag_interval,
		"proxysql_mysql_monitor_replication_lag_interval_seconds",
		"How frequently a replication lag check is performed, in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_replication_lag_timeout,
		"proxysql_mysql_monitor_replication_lag_timeout_seconds",
		"Replication lag check timeout in seconds.",
		metric_tags {}
	),
	std::make_tuple(
		p_th_gauge::mysql_monitor_history,
		"proxysql_mysql_monitor_history_timeout_seconds",
		"The duration for which the events for the checks made by the Monitor module are kept, in seconds.",
		metric_tags {}
	)
	}
);

PgSQL_Threads_Handler::PgSQL_Threads_Handler() {
#ifdef DEBUG
	if (glovars.has_debug == false) {
#else
	if (glovars.has_debug == true) {
#endif /* DEBUG */
		// LCOV_EXCL_START
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
		// LCOV_EXCL_STOP
	}
	num_threads = 0;
	pgsql_threads = NULL;
#ifdef IDLE_THREADS
	pgsql_threads_idles = NULL;
#endif // IDLE_THREADS
	stacksize = 0;
	shutdown_ = 0;
	bootstrapping_listeners = true;
	pthread_rwlock_init(&rwlock, NULL);
	pthread_attr_init(&attr);
	// Zero initialize all variables
	memset(&variables, 0, sizeof(variables));

	variables.authentication_method = (int)AUTHENTICATION_METHOD::SASL_SCRAM_SHA_256; //SCRAM Authentication method
	variables.server_version = strdup((char*)"16.1"); 
	variables.default_client_encoding = strdup((char*)"UTF8");
	variables.shun_on_failures = 5;
	variables.shun_recovery_time_sec = 10;
	variables.unshun_algorithm = 0;
	variables.query_retries_on_failure = 1;
	variables.client_host_cache_size = 0;
	variables.client_host_error_counts = 0;
	variables.handle_warnings = 1;
	variables.connect_retries_on_failure = 10;
	variables.connection_delay_multiplex_ms = 0;
	variables.connection_max_age_ms = 0;
	variables.connect_timeout_client = 10000;
	variables.connect_timeout_server = 1000;
	variables.connect_timeout_server_max = 10000;
	variables.free_connections_pct = 10;
	variables.connect_retries_delay = 1;
	variables.monitor_enabled = true;
	variables.monitor_history = 7200000; // changed in 2.6.0 : was 600000
	variables.monitor_connect_interval = 120000;
	variables.monitor_connect_timeout = 600;
	variables.monitor_ping_interval = 8000;
	variables.monitor_ping_max_failures = 3;
	variables.monitor_ping_timeout = 1000;
    variables.monitor_aws_rds_topology_discovery_interval=1000;
	variables.monitor_read_only_interval = 1000;
	variables.monitor_read_only_timeout = 800;
	variables.monitor_read_only_max_timeout_count = 3;
	variables.monitor_replication_lag_group_by_host = false;
	variables.monitor_replication_lag_interval = 10000;
	variables.monitor_replication_lag_timeout = 1000;
	variables.monitor_replication_lag_count = 1;
/* TODO: Remove
	variables.monitor_groupreplication_healthcheck_interval = 5000;
	variables.monitor_groupreplication_healthcheck_timeout = 800;
	variables.monitor_groupreplication_healthcheck_max_timeout_count = 3;
	variables.monitor_groupreplication_max_transactions_behind_count = 3;
	variables.monitor_groupreplication_max_transactions_behind_for_read_only = 1;
	variables.monitor_galera_healthcheck_interval = 5000;
	variables.monitor_galera_healthcheck_timeout = 800;
	variables.monitor_galera_healthcheck_max_timeout_count = 3;
	variables.monitor_query_interval = 60000;
	variables.monitor_query_timeout = 100;
	variables.monitor_slave_lag_when_null = 60;
	variables.monitor_threads_min = 8;
	variables.monitor_threads_max = 128;
	variables.monitor_threads_queue_maxsize = 128;
*/
	variables.monitor_threads = 2;
	variables.monitor_local_dns_cache_ttl = 300000;
	variables.monitor_local_dns_cache_refresh_interval = 60000;
	variables.monitor_local_dns_resolver_queue_maxsize = 128;
	variables.monitor_username = strdup((char*)"monitor");
	variables.monitor_password = strdup((char*)"monitor");
/* TODO: Remove
	variables.monitor_replication_lag_use_percona_heartbeat = strdup((char*)"");
*/
	variables.monitor_wait_timeout = true;
	variables.monitor_writer_is_also_reader = true;
	variables.max_allowed_packet = 64 * 1024 * 1024;
	variables.automatic_detect_sqli = false;
	variables.firewall_whitelist_enabled = false;
	variables.firewall_whitelist_errormsg = strdup((char*)"Firewall blocked this query");
	variables.use_tcp_keepalive = true; // changed in 2.6.0 , was false
	variables.tcp_keepalive_time = 120; // changed in 2.6.0 , was 0
	variables.throttle_connections_per_sec_to_hostgroup = 1000000;
	variables.max_transaction_idle_time = 4 * 3600 * 1000;
	variables.max_transaction_time = 4 * 3600 * 1000;
	variables.hostgroup_manager_verbose = 1;
	variables.binlog_reader_connect_retry_msec = 3000;
	variables.threshold_query_length = 512 * 1024;
	variables.threshold_resultset_size = 4 * 1024 * 1024;
	variables.query_digests_max_digest_length = 2 * 1024;
	variables.query_digests_max_query_length = 65000; // legacy default
	variables.query_rules_fast_routing_algorithm = 1;
	variables.wait_timeout = 8 * 3600 * 1000;
	variables.throttle_max_bytes_per_second_to_client = 0;
	variables.throttle_ratio_server_to_client = 0;
	variables.connection_warming = false;
	variables.max_connections = 10 * 1000;
	variables.max_stmts_per_connection = 20;
	variables.max_stmts_cache = 10000;
	variables.mirror_max_concurrency = 16;
	variables.mirror_max_queue_length = 32000;
	variables.default_max_latency_ms = 1 * 1000; // by default, the maximum allowed latency for a host is 1000ms
	variables.default_query_delay = 0;
	variables.default_query_timeout = 24 * 3600 * 1000;
	variables.query_processor_iterations = 0;
	variables.query_processor_regex = 1;
	variables.set_query_lock_on_hostgroup = 1;
	variables.set_parser_algorithm = 2; // before 2.6.0 this was 1
	variables.auto_increment_delay_multiplex = 5;
	variables.auto_increment_delay_multiplex_timeout_ms = 10000;
	variables.long_query_time = 1000;
	variables.query_cache_size_MB = 256;
	variables.query_cache_soft_ttl_pct = 0;
	variables.query_cache_handle_warnings = 0;
	variables.init_connect = NULL;
	variables.ldap_user_variable = NULL;
	variables.add_ldap_user_comment = NULL;
	for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		variables.default_variables[i] = strdup(mysql_tracked_variables[i].default_value);
	}
	variables.default_session_track_gtids = strdup((char*)MYSQL_DEFAULT_SESSION_TRACK_GTIDS);
	variables.ping_interval_server_msec = 10000;
	variables.ping_timeout_server = 200;
	variables.default_schema = strdup((char*)"information_schema");
	variables.handle_unknown_charset = 1;
	variables.interfaces = strdup((char*)"");
	variables.eventslog_filename = strdup((char*)""); // proxysql-mysql-eventslog is recommended
	variables.eventslog_filesize = 100 * 1024 * 1024;
	variables.eventslog_default_log = 0;
	variables.eventslog_format = 1;
	variables.auditlog_filename = strdup((char*)"");
	variables.auditlog_filesize = 100 * 1024 * 1024;
	//variables.server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
	// major upgrade in 2.0.0
	variables.server_capabilities = CLIENT_MYSQL | CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH;;
	variables.poll_timeout = 2000;
	variables.poll_timeout_on_failure = 100;
	variables.have_compress = true;
	variables.have_ssl = true; // changed in 2.6.0 , was false by default for performance reason
	variables.commands_stats = true;
	variables.multiplexing = true;
	variables.log_unhealthy_connections = true;
	variables.enforce_autocommit_on_reads = false;
	variables.autocommit_false_not_reusable = false;
	variables.autocommit_false_is_transaction = false;
	variables.verbose_query_error = false;
	variables.query_digests = true;
	variables.query_digests_lowercase = false;
	variables.query_digests_replace_null = false;
	variables.query_digests_no_digits = false;
	variables.query_digests_normalize_digest_text = false;
	variables.query_digests_track_hostname = false;
	variables.query_digests_keep_comment = false;
	variables.parse_failure_logs_digest = false;
	variables.min_num_servers_lantency_awareness = 1000;
	variables.aurora_max_lag_ms_only_read_from_replicas = 2;
	variables.stats_time_backend_query = false;
	variables.stats_time_query_processor = false;
	variables.query_cache_stores_empty_result = true;
	variables.kill_backend_connection_when_disconnect = true;
	variables.client_session_track_gtid = true;
	variables.sessions_sort = true;
#ifdef IDLE_THREADS
	variables.session_idle_ms = 1;
	variables.session_idle_show_processlist = true;
#endif // IDLE_THREADS
	variables.show_processlist_extended = 0;
	variables.servers_stats = true;
	variables.default_reconnect = true;
	variables.ssl_p2s_ca = NULL;
	variables.ssl_p2s_capath = NULL;
	variables.ssl_p2s_cert = NULL;
	variables.ssl_p2s_key = NULL;
	variables.ssl_p2s_cipher = NULL;
	variables.ssl_p2s_crl = NULL;
	variables.ssl_p2s_crlpath = NULL;
	variables.keep_multiplexing_variables = strdup((char*)"tx_isolation,transaction_isolation,version");
#ifdef DEBUG
	variables.session_debug = true;
#endif /*debug */
	variables.query_digests_grouping_limit = 3;
	variables.query_digests_groups_grouping_limit = 10; // changed in 2.6.0 , was 0
	variables.enable_client_deprecate_eof = true;
	variables.enable_server_deprecate_eof = true;
	variables.enable_load_data_local_infile = false;
	variables.log_mysql_warnings_enabled = false;
	variables.data_packets_history_size = 0;
	// status variables
	status_variables.mirror_sessions_current = 0;
	__global_PgSQL_Thread_Variables_version = 1;
	MLM = new PgSQL_Listeners_Manager();

	// Initialize prometheus metrics
	//init_prometheus_counter_array<th_metrics_map_idx, p_th_counter>(th_metrics_map, this->status_variables.p_counter_array);
	//init_prometheus_gauge_array<th_metrics_map_idx, p_th_gauge>(th_metrics_map, this->status_variables.p_gauge_array);

	// Init client_host_cache mutex
	pthread_mutex_init(&mutex_client_host_cache, NULL);
	}

unsigned int PgSQL_Threads_Handler::get_global_version() {
	return __sync_fetch_and_add(&__global_PgSQL_Thread_Variables_version, 0);
}

int PgSQL_Threads_Handler::listener_add(const char* address, int port) {
	char* s = (char*)malloc(strlen(address) + 32);
	sprintf(s, "%s:%d", address, port);
	int ret = listener_add((const char*)s);
	free(s);
	return ret;
}

int PgSQL_Threads_Handler::listener_add(const char* iface) {
	int rc;
	int* perthrsocks = NULL;;
	rc = MLM->add(iface, num_threads, &perthrsocks);
	if (rc > -1) {
		unsigned int i;
		if (perthrsocks == NULL) {
			for (i = 0; i < num_threads; i++) {
				PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
				while (!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_add, 0, rc)) {
					usleep(10); // pause a bit
				}
			}
		}
		else {
			for (i = 0; i < num_threads; i++) {
				PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
				while (!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_add, 0, perthrsocks[i])) {
					usleep(10); // pause a bit
				}
			}
			free(perthrsocks);
		}
	}
	return rc;
}

int PgSQL_Threads_Handler::listener_del(const char* iface) {
	int idx;
	while ((idx = MLM->find_idx(iface)) >= 0) {
		unsigned int i;
		int fd = MLM->get_fd(idx);
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
#ifdef SO_REUSEPORT
			if (GloVars.global.reuseport)
				while (!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_del, 0, -1));
			else
#endif
				while (!__sync_bool_compare_and_swap(&thr->mypolls.pending_listener_del, 0, fd));
		}
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			while (__sync_fetch_and_add(&thr->mypolls.pending_listener_del, 0));
		}
		MLM->del(idx);
#ifdef SO_REUSEPORT
		if (GloVars.global.reuseport) {
			continue;
		}
#endif
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
	return 0;
}

void PgSQL_Threads_Handler::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void PgSQL_Threads_Handler::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

void PgSQL_Threads_Handler::commit() {
	__sync_add_and_fetch(&__global_PgSQL_Thread_Variables_version, 1);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 1, "Increasing version number to %d - all threads will notice this and refresh their variables\n", __global_PgSQL_Thread_Variables_version);
}

char* PgSQL_Threads_Handler::get_variable_string(char* name) {
	if (!strncmp(name, "monitor_", 8)) {
		if (!strcmp(name, "monitor_username")) return strdup(variables.monitor_username);
		if (!strcmp(name, "monitor_password")) return strdup(variables.monitor_password);
/*
		if (!strcmp(name, "monitor_replication_lag_use_percona_heartbeat")) return strdup(variables.monitor_replication_lag_use_percona_heartbeat);
*/
	}
	if (!strncmp(name, "ssl_", 4)) {
		if (!strcmp(name, "ssl_p2s_ca")) {
			if (variables.ssl_p2s_ca == NULL || strlen(variables.ssl_p2s_ca) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_ca);
			}
		}
		if (!strcmp(name, "ssl_p2s_cert")) {
			if (variables.ssl_p2s_cert == NULL || strlen(variables.ssl_p2s_cert) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_cert);
			}
		}
		if (!strcmp(name, "ssl_p2s_capath")) {
			if (variables.ssl_p2s_capath == NULL || strlen(variables.ssl_p2s_capath) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_capath);
			}
		}
		if (!strcmp(name, "ssl_p2s_key")) {
			if (variables.ssl_p2s_key == NULL || strlen(variables.ssl_p2s_key) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_key);
			}
		}
		if (!strcmp(name, "ssl_p2s_cipher")) {
			if (variables.ssl_p2s_cipher == NULL || strlen(variables.ssl_p2s_cipher) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_cipher);
			}
		}
		if (!strcmp(name, "ssl_p2s_crl")) {
			if (variables.ssl_p2s_crl == NULL || strlen(variables.ssl_p2s_crl) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_crl);
			}
		}
		if (!strcmp(name, "ssl_p2s_crlpath")) {
			if (variables.ssl_p2s_crlpath == NULL || strlen(variables.ssl_p2s_crlpath) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_crlpath);
			}
		}
	}
	if (!strcmp(name, "firewall_whitelist_errormsg")) {
		if (variables.firewall_whitelist_errormsg == NULL || strlen(variables.firewall_whitelist_errormsg) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.firewall_whitelist_errormsg);
		}
	}
	if (!strcmp(name, "init_connect")) {
		if (variables.init_connect == NULL || strlen(variables.init_connect) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.init_connect);
		}
	}
	if (!strcmp(name, "ldap_user_variable")) {
		if (variables.ldap_user_variable == NULL || strlen(variables.ldap_user_variable) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.ldap_user_variable);
		}
	}
	if (!strcmp(name, "add_ldap_user_comment")) {
		if (variables.add_ldap_user_comment == NULL || strlen(variables.add_ldap_user_comment) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.add_ldap_user_comment);
		}
	}
	if (!strncmp(name, "default_", 8)) {
		for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
			if (mysql_tracked_variables[i].is_global_variable == false)
				continue;
			char buf[128];
			sprintf(buf, "default_%s", mysql_tracked_variables[i].internal_variable_name);
			if (!strcmp(name, buf)) {
				if (variables.default_variables[i] == NULL) {
					variables.default_variables[i] = strdup(mysql_tracked_variables[i].default_value);
				}
				return strdup(variables.default_variables[i]);
			}
		}
		if (!strcmp(name, "default_session_track_gtids")) {
			if (variables.default_session_track_gtids == NULL) {
				variables.default_session_track_gtids = strdup((char*)MYSQL_DEFAULT_SESSION_TRACK_GTIDS);
			}
			return strdup(variables.default_session_track_gtids);
		}
		if (!strcmp(name, "default_schema")) return strdup(variables.default_schema);
	}
	if (!strcmp(name, "server_version")) return strdup(variables.server_version);
	if (!strcmp(name, "default_client_encoding")) return strdup(variables.default_client_encoding);
	if (!strcmp(name, "eventslog_filename")) return strdup(variables.eventslog_filename);
	if (!strcmp(name, "auditlog_filename")) return strdup(variables.auditlog_filename);
	if (!strcmp(name, "interfaces")) return strdup(variables.interfaces);
	if (!strcmp(name, "keep_multiplexing_variables")) return strdup(variables.keep_multiplexing_variables);
	// LCOV_EXCL_START
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return NULL;
	// LCOV_EXCL_STOP
}

uint16_t PgSQL_Threads_Handler::get_variable_uint16(char* name) {
	if (!strcasecmp(name, "server_capabilities")) return variables.server_capabilities;
	// LCOV_EXCL_START
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
	// LCOV_EXCL_STOP
}

int PgSQL_Threads_Handler::get_variable_int(const char* name) {
	// convert name to string, and lowercase
	std::string nameS = string(name);
	std::transform(nameS.begin(), nameS.end(), nameS.begin(), [](unsigned char c) { return std::tolower(c); });
	{
		// integer variable
		std::unordered_map<std::string, std::tuple<int*, int, int, bool>>::const_iterator it = VariablesPointers_int.find(nameS);
		if (it != VariablesPointers_int.end()) {
			int* v = std::get<0>(it->second);
			return *v;
		}
	}
	{
		// bool variable
		std::unordered_map<std::string, std::tuple<bool*, bool>>::const_iterator it = VariablesPointers_bool.find(nameS);
		if (it != VariablesPointers_bool.end()) {
			bool* v = std::get<0>(it->second);
			int a = (int)*v;
			return a;
		}
	}


	//VALGRIND_DISABLE_ERROR_REPORTING;
	if (!strcmp(name, "stacksize")) return (stacksize ? stacksize : DEFAULT_STACK_SIZE);
	// LCOV_EXCL_START
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
	// LCOV_EXCL_STOP
//VALGRIND_ENABLE_ERROR_REPORTING;
}

char* PgSQL_Threads_Handler::get_variable(char* name) {	// this is the public function, accessible from admin
	//VALGRIND_DISABLE_ERROR_REPORTING;
#define INTBUFSIZE	4096
	char intbuf[INTBUFSIZE];

	// convert name to string, and lowercase
	std::string nameS = string(name);
	std::transform(nameS.begin(), nameS.end(), nameS.begin(), [](unsigned char c) { return std::tolower(c); });

	{
		// integer variable
		std::unordered_map<std::string, std::tuple<int*, int, int, bool>>::const_iterator it = VariablesPointers_int.find(nameS);
		if (it != VariablesPointers_int.end()) {
			int* v = std::get<0>(it->second);
			sprintf(intbuf, "%d", *v);
			return strdup(intbuf);
		}
	}
	{
		// bool variable
		std::unordered_map<std::string, std::tuple<bool*, bool>>::const_iterator it = VariablesPointers_bool.find(nameS);
		if (it != VariablesPointers_bool.end()) {
			bool* v = std::get<0>(it->second);
			return strdup((*v ? "true" : "false"));
		}
	}


	if (!strcasecmp(name, "firewall_whitelist_errormsg")) {
		if (variables.firewall_whitelist_errormsg == NULL || strlen(variables.firewall_whitelist_errormsg) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.firewall_whitelist_errormsg);
		}
	}
	if (!strcasecmp(name, "init_connect")) {
		if (variables.init_connect == NULL || strlen(variables.init_connect) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.init_connect);
		}
	}
	if (!strcasecmp(name, "ldap_user_variable")) {
		if (variables.ldap_user_variable == NULL || strlen(variables.ldap_user_variable) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.ldap_user_variable);
		}
	}
	if (!strcasecmp(name, "add_ldap_user_comment")) {
		if (variables.add_ldap_user_comment == NULL || strlen(variables.add_ldap_user_comment) == 0) {
			return NULL;
		}
		else {
			return strdup(variables.add_ldap_user_comment);
		}
	}
	if (!strcasecmp(name, "default_session_track_gtids")) {
		if (variables.default_session_track_gtids == NULL) {
			variables.default_session_track_gtids = strdup((char*)MYSQL_DEFAULT_SESSION_TRACK_GTIDS);
		}
		return strdup(variables.default_session_track_gtids);
	}
	if (strlen(name) > 8) {
		if (strncmp(name, "default_", 8) == 0) {
			for (unsigned int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
				if (mysql_tracked_variables[i].is_global_variable) {
					size_t var_len = strlen(mysql_tracked_variables[i].internal_variable_name);
					if (strlen(name) == (var_len + 8)) {
						if (!strncmp(name + 8, mysql_tracked_variables[i].internal_variable_name, var_len)) {
							return strdup(variables.default_variables[i]);
						}
					}
				}
			}
		}
	}
	if (!strcasecmp(name, "firewall_whitelist_errormsg")) return strdup(variables.firewall_whitelist_errormsg);
	if (!strcasecmp(name, "server_version")) return strdup(variables.server_version);
	if (!strcasecmp(name, "default_client_encoding")) return strdup(variables.default_client_encoding);
	if (!strcasecmp(name, "auditlog_filename")) return strdup(variables.auditlog_filename);
	if (!strcasecmp(name, "eventslog_filename")) return strdup(variables.eventslog_filename);
	if (!strcasecmp(name, "default_schema")) return strdup(variables.default_schema);
	if (!strcasecmp(name, "keep_multiplexing_variables")) return strdup(variables.keep_multiplexing_variables);
	if (!strcasecmp(name, "interfaces")) return strdup(variables.interfaces);
	if (!strcasecmp(name, "server_capabilities")) {
		// FIXME : make it human readable
		sprintf(intbuf, "%d", variables.server_capabilities);
		return strdup(intbuf);
	}
	// SSL variables
	if (!strncasecmp(name, "ssl_", 4)) {
		if (!strcasecmp(name, "ssl_p2s_ca")) {
			if (variables.ssl_p2s_ca == NULL || strlen(variables.ssl_p2s_ca) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_ca);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_capath")) {
			if (variables.ssl_p2s_capath == NULL || strlen(variables.ssl_p2s_capath) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_capath);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_cert")) {
			if (variables.ssl_p2s_cert == NULL || strlen(variables.ssl_p2s_cert) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_cert);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_key")) {
			if (variables.ssl_p2s_key == NULL || strlen(variables.ssl_p2s_key) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_key);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_cipher")) {
			if (variables.ssl_p2s_cipher == NULL || strlen(variables.ssl_p2s_cipher) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_cipher);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_crl")) {
			if (variables.ssl_p2s_crl == NULL || strlen(variables.ssl_p2s_crl) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_crl);
			}
		}
		if (!strcasecmp(name, "ssl_p2s_crlpath")) {
			if (variables.ssl_p2s_crlpath == NULL || strlen(variables.ssl_p2s_crlpath) == 0) {
				return NULL;
			}
			else {
				return strdup(variables.ssl_p2s_crlpath);
			}
		}
	}
	// monitor variables
	if (!strncasecmp(name, "monitor_", 8)) {
		if (!strcasecmp(name, "monitor_username")) return strdup(variables.monitor_username);
		if (!strcasecmp(name, "monitor_password")) return strdup(variables.monitor_password);
/*
		if (!strcasecmp(name, "monitor_replication_lag_use_percona_heartbeat")) return strdup(variables.monitor_replication_lag_use_percona_heartbeat);
*/
	}
	if (!strcasecmp(name, "threads")) {
		sprintf(intbuf, "%d", (num_threads ? num_threads : DEFAULT_NUM_THREADS));
		return strdup(intbuf);
	}
	if (!strcasecmp(name, "stacksize")) {
		sprintf(intbuf, "%d", (int)(stacksize ? stacksize : DEFAULT_STACK_SIZE));
		return strdup(intbuf);
	}

	return NULL;
	//VALGRIND_ENABLE_ERROR_REPORTING;
}



bool PgSQL_Threads_Handler::set_variable(char* name, const char* value) {	// this is the public function, accessible from admin
	// IN:
	// name: variable name
	// value: variable value
	//
	// OUT:
	// false: unable to change the variable value, either because doesn't exist, or because out of range, or read only
	// true: variable value changed
	//
	if (!value) return false;
	size_t vallen = strlen(value);


	// convert name to string, and lowercase
	std::string nameS = string(name);
	std::transform(nameS.begin(), nameS.end(), nameS.begin(), [](unsigned char c) { return std::tolower(c); });
	{
		// integer variable ?
		std::unordered_map<std::string, std::tuple<int*, int, int, bool>>::const_iterator it = VariablesPointers_int.find(nameS);
		if (it != VariablesPointers_int.end()) {
			// Log warnings for variables with possibly wrong values
			if (nameS == "auto_increment_delay_multiplex_timeout_ms") {
				int intv = atoi(value);
				if (intv <= 60) {
					proxy_warning("'mysql-auto_increment_delay_multiplex_timeout_ms' is set to a low value: %ums. Remember value is in 'ms'\n", intv);
				}
			}
			if (nameS == "query_rules_fast_routing_algorithm") {
				if (GloPgQPro) {
					int intv = atoi(value);
					if (intv >= std::get<1>(it->second) && intv <= std::get<2>(it->second)) {
						GloPgQPro->wrlock();
						GloPgQPro->query_rules_fast_routing_algorithm = intv;
						GloPgQPro->wrunlock();
					}
				}
			}
			bool special_variable = std::get<3>(it->second); // if special_variable is true, min and max values are ignored, and more input validation is needed
			if (special_variable == false) {
				int intv = atoi(value);
				if (intv >= std::get<1>(it->second) && intv <= std::get<2>(it->second)) {
					int* v = std::get<0>(it->second);
					*v = intv;
					return true;
				}
				return false;
			}
			else {
				// we need to perform input validation
			}
		}
	}
	{
		// boolean variable ?
		std::unordered_map<std::string, std::tuple<bool*, bool>>::const_iterator it = VariablesPointers_bool.find(nameS);
		if (it != VariablesPointers_bool.end()) {
			bool special_variable = std::get<1>(it->second); // if special_variable is true, more input validation is needed
			if (special_variable == false) {
				bool* v = std::get<0>(it->second);
				if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
					*v = true;
					return true;
				}
				if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
					*v = false;
					return true;
				}
				return false;
			}
			else {
				// we need to perform input validation
			}
		}
	}

	// monitor variables
	if (!strncasecmp(name, "monitor_", 8)) {
		if (!strcasecmp(name, "monitor_username")) {
			if (vallen) {
				free(variables.monitor_username);
				variables.monitor_username = strdup(value);
				return true;
			}
			else {
				return false;
			}
		}
		if (!strcasecmp(name, "monitor_password")) {
			free(variables.monitor_password);
			variables.monitor_password = strdup(value);
			return true;
		}
		if (!strcasecmp(name, "monitor_replication_lag_use_percona_heartbeat")) {
			if (vallen == 0) { // empty string
				free(variables.monitor_replication_lag_use_percona_heartbeat);
				variables.monitor_replication_lag_use_percona_heartbeat = strdup((value));
				return true;
			}
			else {
				re2::RE2::Options* opt2 = new re2::RE2::Options(RE2::Quiet);
				opt2->set_case_sensitive(false);
				char* patt = (char*)"`?([a-z\\d_]+)`?\\.`?([a-z\\d_]+)`?";
				RE2* re = new RE2(patt, *opt2);
				bool rc = false;
				rc = RE2::FullMatch(value, *re);
				delete re;
				delete opt2;
				if (rc) {
					free(variables.monitor_replication_lag_use_percona_heartbeat);
					variables.monitor_replication_lag_use_percona_heartbeat = strdup(value);
					return true;
				}
				else {
					proxy_error("%s is an invalid value for %s, not matching regex \"%s\"\n", value, name, patt);
				}
			}
			return false;
		}
	}
	if (!strcasecmp(name, "binlog_reader_connect_retry_msec")) {
		int intv = atoi(value);
		if (intv >= 200 && intv <= 120000) {
			__sync_lock_test_and_set(&variables.binlog_reader_connect_retry_msec, intv);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "wait_timeout")) {
		int intv = atoi(value);
		if (intv >= 0 && intv <= 20 * 24 * 3600 * 1000) {
			variables.wait_timeout = intv;
			if (variables.wait_timeout < 5000) {
				proxy_warning("mysql-wait_timeout is set to a low value: %ums\n", variables.wait_timeout);
			}
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "eventslog_format")) {
		int intv = atoi(value);
		if (intv >= 1 && intv <= 2) {
			if (variables.eventslog_format != intv) {
				// if we are switching format, we need to switch file too
				if (GloPgSQL_Logger) {
					proxy_info("Switching query logging format from %d to %d\n", variables.eventslog_format, intv);
					GloPgSQL_Logger->flush_log();
				}
				variables.eventslog_format = intv;
			}
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "default_schema")) {
		if (vallen) {
			free(variables.default_schema);
			variables.default_schema = strdup(value);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "interfaces")) {
		if (vallen && strlen(variables.interfaces) == 0) {
			free(variables.interfaces);
			variables.interfaces = strdup(value);
			return true;
		}
		else {
			if (vallen && strcmp(value, variables.interfaces) == 0) {
				return true;
			}
			else {
				return false;
			}
		}
	}
	if (!strcasecmp(name, "server_version")) {
		if (vallen) {
			free(variables.server_version);
			variables.server_version = strdup(value);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "default_client_encoding")) {
		if (vallen) {
			free(variables.default_client_encoding);
			variables.default_client_encoding = strdup(value);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "init_connect")) {
		if (variables.init_connect) free(variables.init_connect);
		variables.init_connect = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.init_connect = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "firewall_whitelist_errormsg")) {
		if (variables.firewall_whitelist_errormsg) free(variables.firewall_whitelist_errormsg);
		variables.firewall_whitelist_errormsg = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.firewall_whitelist_errormsg = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ldap_user_variable")) {
		if (variables.ldap_user_variable) free(variables.ldap_user_variable);
		variables.ldap_user_variable = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ldap_user_variable = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "add_ldap_user_comment")) {
		if (variables.add_ldap_user_comment) free(variables.add_ldap_user_comment);
		variables.add_ldap_user_comment = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.add_ldap_user_comment = strdup(value);
		}
		return true;
	}

	if (!strcasecmp(name, "default_session_track_gtids")) {
		if (variables.default_session_track_gtids) free(variables.default_session_track_gtids);
		variables.default_session_track_gtids = NULL;
		if (vallen) {
			// we only accept 2 value for session_track_gtids = OFF or OWN_GTID
			if (strcasecmp(value, (char*)"OFF") == 0) {
				// for convention, we stored the value as uppercase
				variables.default_session_track_gtids = strdup((char*)"OFF");
				return true;
			}
			else if (strcasecmp(value, (char*)"OWN_GTID") == 0) {
				// for convention, we stored the value as uppercase
				variables.default_session_track_gtids = strdup((char*)"OWN_GTID");
				return true;
			}
		}
		return false; // we couldn't set it to a valid value. It will be reset to default
	}

	if (!strncmp(name, "default_", 8)) {
		for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
			if (mysql_tracked_variables[i].is_global_variable == false)
				continue;
			char buf[128];
			sprintf(buf, "default_%s", mysql_tracked_variables[i].internal_variable_name);
			if (!strcmp(name, buf)) {
				if (variables.default_variables[i]) free(variables.default_variables[i]);
				variables.default_variables[i] = NULL;
				if (vallen) {
					if (strcmp(value, "(null)"))
						variables.default_variables[i] = strdup(value);
				}
				if (variables.default_variables[i] == NULL)
					variables.default_variables[i] = strdup(mysql_tracked_variables[i].default_value);
				return true;
			}
		}
	}


	if (!strcasecmp(name, "keep_multiplexing_variables")) {
		if (vallen) {
			free(variables.keep_multiplexing_variables);
			variables.keep_multiplexing_variables = strdup(value);
			return true;
		}
		else {
			return false;
		}
	}
	// SSL proxy to server variables
	if (!strcasecmp(name, "ssl_p2s_ca")) {
		if (variables.ssl_p2s_ca) free(variables.ssl_p2s_ca);
		variables.ssl_p2s_ca = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_ca = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_capath")) {
		if (variables.ssl_p2s_capath) free(variables.ssl_p2s_capath);
		variables.ssl_p2s_capath = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_capath = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_cert")) {
		if (variables.ssl_p2s_cert) free(variables.ssl_p2s_cert);
		variables.ssl_p2s_cert = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_cert = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_key")) {
		if (variables.ssl_p2s_key) free(variables.ssl_p2s_key);
		variables.ssl_p2s_key = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_key = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_cipher")) {
		if (variables.ssl_p2s_cipher) free(variables.ssl_p2s_cipher);
		variables.ssl_p2s_cipher = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_cipher = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_crl")) {
		if (variables.ssl_p2s_crl) free(variables.ssl_p2s_crl);
		variables.ssl_p2s_crl = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_crl = strdup(value);
		}
		return true;
	}
	if (!strcasecmp(name, "ssl_p2s_crlpath")) {
		if (variables.ssl_p2s_crlpath) free(variables.ssl_p2s_crlpath);
		variables.ssl_p2s_crlpath = NULL;
		if (vallen) {
			if (strcmp(value, "(null)"))
				variables.ssl_p2s_crlpath = strdup(value);
		}
		return true;
	}

	if (!strcasecmp(name, "auditlog_filename")) {
		if (value[strlen(value) - 1] == '/') {
			proxy_error("%s is an invalid value for auditlog_filename, please specify a filename not just the path\n", value);
			return false;
		}
		else if (value[0] == '/') {
			char* full_path = strdup(value);
			char* eval_dirname = dirname(full_path);
			DIR* eventlog_dir = opendir(eval_dirname);
			if (eventlog_dir) {
				closedir(eventlog_dir);
				free(variables.auditlog_filename);
				variables.auditlog_filename = strdup(value);
				free(full_path);
				return true;
			}
			else {
				proxy_error("%s is an invalid value for auditlog_filename path, the directory cannot be accessed\n", eval_dirname);
				return false;
			}
		}
		else {
			free(variables.auditlog_filename);
			variables.auditlog_filename = strdup(value);
			return true;
		}
	}
	if (!strcasecmp(name, "eventslog_filename")) {
		if (value[strlen(value) - 1] == '/') {
			proxy_error("%s is an invalid value for eventslog_filename, please specify a filename not just the path\n", value);
			return false;
		}
		else if (value[0] == '/') {
			char* full_path = strdup(value);
			char* eval_dirname = dirname(full_path);
			DIR* eventlog_dir = opendir(eval_dirname);
			if (eventlog_dir) {
				closedir(eventlog_dir);
				free(variables.eventslog_filename);
				variables.eventslog_filename = strdup(value);
				free(full_path);
				return true;
			}
			else {
				proxy_error("%s is an invalid value for eventslog_filename path, the directory cannot be accessed\n", eval_dirname);
				return false;
			}
		}
		else {
			free(variables.eventslog_filename);
			variables.eventslog_filename = strdup(value);
			return true;
		}
	}
	if (!strcasecmp(name, "server_capabilities")) {
		// replaced atoi() with strtoul() to have a 32 bit result
		uint32_t intv = strtoul(value, NULL, 10);
		if (intv > 10) {
			// Note that:
			// - some capabilities are changed at runtime while performing the handshake with the client
			// - even if we support 32 bits capabilities, many of them do not have any real meaning for proxysql (not supported)
			variables.server_capabilities = intv;
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "stacksize")) {
		int intv = atoi(value);
		if (intv >= 256 * 1024 && intv <= 4 * 1024 * 1024) {
			stacksize = intv;
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "threads")) {
		unsigned int intv = atoi(value);
		if ((num_threads == 0 || num_threads == intv || pgsql_threads == NULL) && intv > 0 && intv < 256) {
			num_threads = intv;
			//this->status_variables.p_gauge_array[p_th_gauge::mysql_thread_workers]->Set(intv);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name, "have_compress")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.have_compress = true;
			variables.server_capabilities |= CLIENT_COMPRESS;
			return true;
		}
		if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.have_compress = false;
			variables.server_capabilities &= ~CLIENT_COMPRESS;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name, "have_ssl")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			variables.have_ssl = true;
			variables.server_capabilities |= CLIENT_SSL;
			return true;
		}
		if (strcasecmp(value, "false") == 0 || strcasecmp(value, "0") == 0) {
			variables.have_ssl = false;
			variables.server_capabilities &= ~CLIENT_SSL;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name, "forward_autocommit")) {
		if (strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
			proxy_error("Variable mysql-forward_autocommit is deprecated. See issue #3253\n");
			return false;
		}
		return false;
	}
	if (!strcasecmp(name, "data_packets_history_size")) {
		int intv = atoi(value);
		if (intv >= 0 && intv < INT_MAX) {
			variables.data_packets_history_size = intv;
			GloVars.global.data_packets_history_size = intv;
			return true;
		}
		else {
			return false;
		}
	}
	return false;
}


// return variables from both pgsql_thread_variables_names AND mysql_tracked_variables
char** PgSQL_Threads_Handler::get_variables_list() {


	// initialize VariablesPointers_bool
	// it is safe to do it here because get_variables_list() is the first function called during start time
	if (VariablesPointers_bool.size() == 0) {
		VariablesPointers_bool["autocommit_false_is_transaction"] = make_tuple(&variables.autocommit_false_is_transaction, false);
		VariablesPointers_bool["autocommit_false_not_reusable"] = make_tuple(&variables.autocommit_false_not_reusable, false);
		VariablesPointers_bool["automatic_detect_sqli"] = make_tuple(&variables.automatic_detect_sqli, false);
		VariablesPointers_bool["client_session_track_gtid"] = make_tuple(&variables.client_session_track_gtid, false);
		VariablesPointers_bool["commands_stats"] = make_tuple(&variables.commands_stats, false);
		VariablesPointers_bool["connection_warming"] = make_tuple(&variables.connection_warming, false);
		VariablesPointers_bool["default_reconnect"] = make_tuple(&variables.default_reconnect, false);
		VariablesPointers_bool["enable_client_deprecate_eof"] = make_tuple(&variables.enable_client_deprecate_eof, false);
		VariablesPointers_bool["enable_server_deprecate_eof"] = make_tuple(&variables.enable_server_deprecate_eof, false);
		VariablesPointers_bool["enable_load_data_local_infile"] = make_tuple(&variables.enable_load_data_local_infile, false);
		VariablesPointers_bool["enforce_autocommit_on_reads"] = make_tuple(&variables.enforce_autocommit_on_reads, false);
		VariablesPointers_bool["firewall_whitelist_enabled"] = make_tuple(&variables.firewall_whitelist_enabled, false);
		VariablesPointers_bool["kill_backend_connection_when_disconnect"] = make_tuple(&variables.kill_backend_connection_when_disconnect, false);
		VariablesPointers_bool["log_mysql_warnings_enabled"] = make_tuple(&variables.log_mysql_warnings_enabled, false);
		VariablesPointers_bool["log_unhealthy_connections"] = make_tuple(&variables.log_unhealthy_connections, false);
		VariablesPointers_bool["monitor_enabled"] = make_tuple(&variables.monitor_enabled, false);
		VariablesPointers_bool["monitor_replication_lag_group_by_host"] = make_tuple(&variables.monitor_replication_lag_group_by_host, false);
		VariablesPointers_bool["monitor_wait_timeout"] = make_tuple(&variables.monitor_wait_timeout, false);
		VariablesPointers_bool["monitor_writer_is_also_reader"] = make_tuple(&variables.monitor_writer_is_also_reader, false);
		VariablesPointers_bool["multiplexing"] = make_tuple(&variables.multiplexing, false);
		VariablesPointers_bool["query_cache_stores_empty_result"] = make_tuple(&variables.query_cache_stores_empty_result, false);
		VariablesPointers_bool["query_digests"] = make_tuple(&variables.query_digests, false);
		VariablesPointers_bool["query_digests_lowercase"] = make_tuple(&variables.query_digests_lowercase, false);
		VariablesPointers_bool["query_digests_replace_null"] = make_tuple(&variables.query_digests_replace_null, false);
		VariablesPointers_bool["query_digests_no_digits"] = make_tuple(&variables.query_digests_no_digits, false);
		VariablesPointers_bool["query_digests_normalize_digest_text"] = make_tuple(&variables.query_digests_normalize_digest_text, false);
		VariablesPointers_bool["query_digests_track_hostname"] = make_tuple(&variables.query_digests_track_hostname, false);
		VariablesPointers_bool["query_digests_keep_comment"] = make_tuple(&variables.query_digests_keep_comment, false);
		VariablesPointers_bool["parse_failure_logs_digest"] = make_tuple(&variables.parse_failure_logs_digest, false);
		VariablesPointers_bool["servers_stats"] = make_tuple(&variables.servers_stats, false);
		VariablesPointers_bool["sessions_sort"] = make_tuple(&variables.sessions_sort, false);
		VariablesPointers_bool["stats_time_backend_query"] = make_tuple(&variables.stats_time_backend_query, false);
		VariablesPointers_bool["stats_time_query_processor"] = make_tuple(&variables.stats_time_query_processor, false);
		VariablesPointers_bool["use_tcp_keepalive"] = make_tuple(&variables.use_tcp_keepalive, false);
		VariablesPointers_bool["verbose_query_error"] = make_tuple(&variables.verbose_query_error, false);
#ifdef IDLE_THREADS
		VariablesPointers_bool["session_idle_show_processlist"] = make_tuple(&variables.session_idle_show_processlist, false);
#endif // IDLE_THREADS
#ifdef DEBUG
		VariablesPointers_bool["session_debug"] = make_tuple(&variables.session_debug, false);
#endif /* DEBUG */
		// variables with special variable == true
		// the input validation for these variables MUST be EXPLICIT
		VariablesPointers_bool["have_compress"] = make_tuple(&variables.have_compress, true);
		VariablesPointers_bool["have_ssl"] = make_tuple(&variables.have_ssl, true);
	}


	// initialize VariablesPointers_int
	// it is safe to do it here because get_variables_list() is the first function called during start time
	if (VariablesPointers_int.size() == 0) {
		VariablesPointers_int["authentication_method"] = make_tuple(&variables.authentication_method, 1, 3, false);
		// Monitor variables
		VariablesPointers_int["monitor_history"] = make_tuple(&variables.monitor_history, 1000, 7 * 24 * 3600 * 1000, false);

		VariablesPointers_int["monitor_connect_interval"] = make_tuple(&variables.monitor_connect_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_connect_timeout"] = make_tuple(&variables.monitor_connect_timeout, 100, 600 * 1000, false);

		VariablesPointers_int["monitor_ping_interval"] = make_tuple(&variables.monitor_ping_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_ping_timeout"] = make_tuple(&variables.monitor_ping_timeout, 100, 600 * 1000, false);
		VariablesPointers_int["monitor_ping_max_failures"] = make_tuple(&variables.monitor_ping_max_failures, 1, 1000 * 1000, false);

/*
        VariablesPointers_int["monitor_aws_rds_topology_discovery_interval"] = make_tuple(&variables.monitor_aws_rds_topology_discovery_interval, 1, 100000, false);
*/
		VariablesPointers_int["monitor_read_only_interval"] = make_tuple(&variables.monitor_read_only_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_read_only_timeout"] = make_tuple(&variables.monitor_read_only_timeout, 100, 600 * 1000, false);
		VariablesPointers_int["monitor_read_only_max_timeout_count"] = make_tuple(&variables.monitor_read_only_max_timeout_count, 1, 1000 * 1000, false);
/*
		VariablesPointers_int["monitor_replication_lag_interval"] = make_tuple(&variables.monitor_replication_lag_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_replication_lag_timeout"] = make_tuple(&variables.monitor_replication_lag_timeout, 100, 600 * 1000, false);
		VariablesPointers_int["monitor_replication_lag_count"] = make_tuple(&variables.monitor_replication_lag_count, 1, 10, false);

		VariablesPointers_int["monitor_groupreplication_healthcheck_interval"] = make_tuple(&variables.monitor_groupreplication_healthcheck_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_groupreplication_healthcheck_timeout"] = make_tuple(&variables.monitor_groupreplication_healthcheck_timeout, 100, 600 * 1000, false);
		VariablesPointers_int["monitor_groupreplication_healthcheck_max_timeout_count"] = make_tuple(&variables.monitor_groupreplication_healthcheck_max_timeout_count, 1, 10, false);
		VariablesPointers_int["monitor_groupreplication_max_transactions_behind_count"] = make_tuple(&variables.monitor_groupreplication_max_transactions_behind_count, 1, 10, false);
		VariablesPointers_int["monitor_groupreplication_max_transactions_behind_for_read_only"] = make_tuple(&variables.monitor_groupreplication_max_transactions_behind_for_read_only, 0, 2, false);

		VariablesPointers_int["monitor_galera_healthcheck_interval"] = make_tuple(&variables.monitor_galera_healthcheck_interval, 50, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_galera_healthcheck_timeout"] = make_tuple(&variables.monitor_galera_healthcheck_timeout, 50, 600 * 1000, false);
		VariablesPointers_int["monitor_galera_healthcheck_max_timeout_count"] = make_tuple(&variables.monitor_galera_healthcheck_max_timeout_count, 1, 10, false);

		VariablesPointers_int["monitor_query_interval"] = make_tuple(&variables.monitor_query_interval, 100, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_query_timeout"] = make_tuple(&variables.monitor_query_timeout, 100, 600 * 1000, false);
*/

		VariablesPointers_int["monitor_threads"]  = make_tuple(&variables.monitor_threads, 2,  256, false);
/*
		VariablesPointers_int["monitor_threads_min"] = make_tuple(&variables.monitor_threads_min, 2, 256, false);
		VariablesPointers_int["monitor_threads_max"] = make_tuple(&variables.monitor_threads_max, 4, 1024, false);

		VariablesPointers_int["monitor_slave_lag_when_null"] = make_tuple(&variables.monitor_slave_lag_when_null, 0, 604800, false);

		VariablesPointers_int["monitor_threads_queue_maxsize"] = make_tuple(&variables.monitor_threads_queue_maxsize, 16, 1024, false);
*/
		VariablesPointers_int["monitor_local_dns_cache_ttl"] = make_tuple(&variables.monitor_local_dns_cache_ttl, 0, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_local_dns_cache_refresh_interval"] = make_tuple(&variables.monitor_local_dns_cache_refresh_interval, 0, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["monitor_local_dns_resolver_queue_maxsize"] = make_tuple(&variables.monitor_local_dns_resolver_queue_maxsize, 16, 1024, false);
		// mirroring
		VariablesPointers_int["mirror_max_concurrency"] = make_tuple(&variables.mirror_max_concurrency, 1, 8 * 1024, false);
		VariablesPointers_int["mirror_max_queue_length"] = make_tuple(&variables.mirror_max_queue_length, 0, 1024 * 1024, false);
		// query processor and query digest
		VariablesPointers_int["auto_increment_delay_multiplex"] = make_tuple(&variables.auto_increment_delay_multiplex, 0, 1000000, false);
		VariablesPointers_int["auto_increment_delay_multiplex_timeout_ms"] = make_tuple(&variables.auto_increment_delay_multiplex_timeout_ms, 0, 3600 * 1000, false);
		VariablesPointers_int["default_query_delay"] = make_tuple(&variables.default_query_delay, 0, 3600 * 1000, false);
		VariablesPointers_int["default_query_timeout"] = make_tuple(&variables.default_query_timeout, 1000, 20 * 24 * 3600 * 1000, false);
		VariablesPointers_int["query_digests_grouping_limit"] = make_tuple(&variables.query_digests_grouping_limit, 1, 2089, false);
		VariablesPointers_int["query_digests_groups_grouping_limit"] = make_tuple(&variables.query_digests_groups_grouping_limit, 0, 2089, false);
		VariablesPointers_int["query_digests_max_digest_length"] = make_tuple(&variables.query_digests_max_digest_length, 16, 1 * 1024 * 1024, false);
		VariablesPointers_int["query_digests_max_query_length"] = make_tuple(&variables.query_digests_max_query_length, 16, 1 * 1024 * 1024, false);
		VariablesPointers_int["query_rules_fast_routing_algorithm"] = make_tuple(&variables.query_rules_fast_routing_algorithm, 1, 2, false);
		VariablesPointers_int["query_processor_iterations"] = make_tuple(&variables.query_processor_iterations, 0, 1000 * 1000, false);
		VariablesPointers_int["query_processor_regex"] = make_tuple(&variables.query_processor_regex, 1, 2, false);
		VariablesPointers_int["query_retries_on_failure"] = make_tuple(&variables.query_retries_on_failure, 0, 1000, false);
		VariablesPointers_int["set_query_lock_on_hostgroup"] = make_tuple(&variables.set_query_lock_on_hostgroup, 0, 1, false);
		VariablesPointers_int["set_parser_algorithm"] = make_tuple(&variables.set_parser_algorithm, 1, 2, false);

		// throttle
		VariablesPointers_int["throttle_connections_per_sec_to_hostgroup"] = make_tuple(&variables.throttle_connections_per_sec_to_hostgroup, 1, 100 * 1000 * 1000, false);
		VariablesPointers_int["throttle_max_bytes_per_second_to_client"] = make_tuple(&variables.throttle_max_bytes_per_second_to_client, 0, 2147483647, false);
		VariablesPointers_int["throttle_ratio_server_to_client"] = make_tuple(&variables.throttle_ratio_server_to_client, 0, 100, false);
		// backend management
		VariablesPointers_int["default_max_latency_ms"] = make_tuple(&variables.default_max_latency_ms, 0, 20 * 24 * 3600 * 1000, false);
		VariablesPointers_int["free_connections_pct"] = make_tuple(&variables.free_connections_pct, 0, 100, false);
		VariablesPointers_int["poll_timeout"] = make_tuple(&variables.poll_timeout, 10, 20000, false);
		VariablesPointers_int["poll_timeout_on_failure"] = make_tuple(&variables.poll_timeout_on_failure, 10, 20000, false);
		VariablesPointers_int["shun_on_failures"] = make_tuple(&variables.shun_on_failures, 0, 10000000, false);
		VariablesPointers_int["shun_recovery_time_sec"] = make_tuple(&variables.shun_recovery_time_sec, 0, 3600 * 24 * 365, false);
		VariablesPointers_int["unshun_algorithm"] = make_tuple(&variables.unshun_algorithm, 0, 1, false);
		VariablesPointers_int["hostgroup_manager_verbose"] = make_tuple(&variables.hostgroup_manager_verbose, 0, 3, false);
		VariablesPointers_int["tcp_keepalive_time"] = make_tuple(&variables.tcp_keepalive_time, 0, 7200, false);
		VariablesPointers_int["min_num_servers_lantency_awareness"] = make_tuple(&variables.min_num_servers_lantency_awareness, 0, 10000, false);
		VariablesPointers_int["aurora_max_lag_ms_only_read_from_replicas"] = make_tuple(&variables.aurora_max_lag_ms_only_read_from_replicas, 0, 100, false);
		// connection management
		VariablesPointers_int["connect_retries_on_failure"] = make_tuple(&variables.connect_retries_on_failure, 0, 1000, false);
		VariablesPointers_int["connect_retries_delay"] = make_tuple(&variables.connect_retries_delay, 0, 10000, false);
		VariablesPointers_int["connect_timeout_client"] = make_tuple(&variables.connect_timeout_client, 500, 3600 * 1000, false);
		VariablesPointers_int["connect_timeout_server"] = make_tuple(&variables.connect_timeout_server, 10, 120 * 1000, false);
		VariablesPointers_int["connect_timeout_server_max"] = make_tuple(&variables.connect_timeout_server_max, 10, 3600 * 1000, false);
		VariablesPointers_int["connection_delay_multiplex_ms"] = make_tuple(&variables.connection_delay_multiplex_ms, 0, 300 * 1000, false);
		VariablesPointers_int["connection_max_age_ms"] = make_tuple(&variables.connection_max_age_ms, 0, 3600 * 24 * 1000, false);
		VariablesPointers_int["handle_unknown_charset"] = make_tuple(&variables.handle_unknown_charset, 0, HANDLE_UNKNOWN_CHARSET__MAX_HANDLE_VALUE, false);
		VariablesPointers_int["ping_interval_server_msec"] = make_tuple(&variables.ping_interval_server_msec, 1000, 7 * 24 * 3600 * 1000, false);
		VariablesPointers_int["ping_timeout_server"] = make_tuple(&variables.ping_timeout_server, 10, 600 * 1000, false);
		VariablesPointers_int["client_host_cache_size"] = make_tuple(&variables.client_host_cache_size, 0, 1024 * 1024, false);
		VariablesPointers_int["client_host_error_counts"] = make_tuple(&variables.client_host_error_counts, 0, 1024 * 1024, false);
		VariablesPointers_int["handle_warnings"] = make_tuple(&variables.handle_warnings, 0, 1, false);

		// logs
		VariablesPointers_int["auditlog_filesize"] = make_tuple(&variables.auditlog_filesize, 1024 * 1024, 1 * 1024 * 1024 * 1024, false);
		VariablesPointers_int["eventslog_filesize"] = make_tuple(&variables.eventslog_filesize, 1024 * 1024, 1 * 1024 * 1024 * 1024, false);
		VariablesPointers_int["eventslog_default_log"] = make_tuple(&variables.eventslog_default_log, 0, 1, false);
		// various
		VariablesPointers_int["long_query_time"] = make_tuple(&variables.long_query_time, 0, 20 * 24 * 3600 * 1000, false);
		VariablesPointers_int["max_allowed_packet"] = make_tuple(&variables.max_allowed_packet, 8192, 1024 * 1024 * 1024, false);
		VariablesPointers_int["max_connections"] = make_tuple(&variables.max_connections, 1, 1000 * 1000, false);
		VariablesPointers_int["max_stmts_per_connection"] = make_tuple(&variables.max_stmts_per_connection, 1, 1024, false);
		VariablesPointers_int["max_stmts_cache"] = make_tuple(&variables.max_stmts_cache, 128, 1024 * 1024, false);
		VariablesPointers_int["max_transaction_idle_time"] = make_tuple(&variables.max_transaction_idle_time, 1000, 20 * 24 * 3600 * 1000, false);
		VariablesPointers_int["max_transaction_time"] = make_tuple(&variables.max_transaction_time, 1000, 20 * 24 * 3600 * 1000, false);
		VariablesPointers_int["query_cache_size_mb"] = make_tuple(&variables.query_cache_size_MB, 0, 1024 * 10240, false);
		VariablesPointers_int["query_cache_soft_ttl_pct"] = make_tuple(&variables.query_cache_soft_ttl_pct, 0, 100, false);
		VariablesPointers_int["query_cache_handle_warnings"] = make_tuple(&variables.query_cache_handle_warnings, 0, 1, false);

#ifdef IDLE_THREADS
		VariablesPointers_int["session_idle_ms"] = make_tuple(&variables.session_idle_ms, 1, 3600 * 1000, false);
#endif // IDLE_THREADS
		VariablesPointers_int["show_processlist_extended"] = make_tuple(&variables.show_processlist_extended, 0, 2, false);
		VariablesPointers_int["threshold_query_length"] = make_tuple(&variables.threshold_query_length, 1024, 1 * 1024 * 1024 * 1024, false);
		VariablesPointers_int["threshold_resultset_size"] = make_tuple(&variables.threshold_resultset_size, 1024, 1 * 1024 * 1024 * 1024, false);

		// variables with special variable == true
		// the input validation for these variables MUST be EXPLICIT
		VariablesPointers_int["binlog_reader_connect_retry_msec"] = make_tuple(&variables.binlog_reader_connect_retry_msec, 0, 0, true);
		VariablesPointers_int["eventslog_format"] = make_tuple(&variables.eventslog_format, 0, 0, true);
		VariablesPointers_int["wait_timeout"] = make_tuple(&variables.wait_timeout, 0, 0, true);
		VariablesPointers_int["data_packets_history_size"] = make_tuple(&variables.data_packets_history_size, 0, 0, true);

	}


	const size_t l = sizeof(pgsql_thread_variables_names) / sizeof(char*);
	unsigned int i;
	size_t ltv = 0;
	for (i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (mysql_tracked_variables[i].is_global_variable)
			ltv++;
	}
	char** ret = (char**)malloc(sizeof(char*) * (l + ltv)); // not adding + 1 because pgsql_thread_variables_names is already NULL terminated
	size_t fv = 0;
	for (i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (mysql_tracked_variables[i].is_global_variable) {
			char* m = (char*)malloc(strlen(mysql_tracked_variables[i].internal_variable_name) + 1 + strlen((char*)"default_"));
			sprintf(m, "default_%s", mysql_tracked_variables[i].internal_variable_name);
			ret[fv] = m;
			fv++;
		}
	}
	// this is an extra check.
	assert(fv == ltv);
	for (i = ltv; i < l + ltv - 1; i++) {
		ret[i] = (strdup(pgsql_thread_variables_names[i - ltv]));
	}
	ret[l + ltv - 1] = NULL; // last value
	return ret;
}

// Returns true if the given name is the name of an existing mysql variable
// scan both pgsql_thread_variables_names AND mysql_tracked_variables
bool PgSQL_Threads_Handler::has_variable(const char* name) {
	if (strlen(name) > 8) {
		if (strncmp(name, "default_", 8) == 0) {
			for (unsigned int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
				if (mysql_tracked_variables[i].is_global_variable) {
					size_t var_len = strlen(mysql_tracked_variables[i].internal_variable_name);
					if (strlen(name) == (var_len + 8)) {
						if (!strncmp(name + 8, mysql_tracked_variables[i].internal_variable_name, var_len)) {
							return true;
						}
					}
				}
			}
		}
	}
	size_t no_vars = sizeof(pgsql_thread_variables_names) / sizeof(char*);
	for (unsigned int i = 0; i < no_vars - 1; ++i) {
		size_t var_len = strlen(pgsql_thread_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, pgsql_thread_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

void PgSQL_Threads_Handler::print_version() {
	fprintf(stderr, "Standard MySQL Threads Handler rev. %s -- %s -- %s\n", MYSQL_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

void PgSQL_Threads_Handler::init(unsigned int num, size_t stack) {
	if (stack) {
		stacksize = stack;
	}
	else {
		if (stacksize == 0) stacksize = DEFAULT_STACK_SIZE;
	}
	if (num) {
		num_threads = num;
		//this->status_variables.p_gauge_array[p_th_gauge::mysql_thread_workers]->Set(num);
	}
	else {
		if (num_threads == 0) {
			num_threads = DEFAULT_NUM_THREADS; //default
			//this->status_variables.p_gauge_array[p_th_gauge::mysql_thread_workers]->Set(DEFAULT_NUM_THREADS);
		}
	}
	int rc = pthread_attr_setstacksize(&attr, stacksize);
	assert(rc == 0);
	pgsql_threads = (proxysql_pgsql_thread_t*)calloc(num_threads, sizeof(proxysql_pgsql_thread_t));
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		pgsql_threads_idles = (proxysql_pgsql_thread_t*)calloc(num_threads, sizeof(proxysql_pgsql_thread_t));
#endif // IDLE_THREADS
}

proxysql_pgsql_thread_t* PgSQL_Threads_Handler::create_thread(unsigned int tn, void* (*start_routine) (void*), bool idles) {
	if (idles == false) {
		if (pthread_create(&pgsql_threads[tn].thread_id, &attr, start_routine, &pgsql_threads[tn]) != 0) {
			// LCOV_EXCL_START
			proxy_error("Thread creation\n");
			assert(0);
			// LCOV_EXCL_STOP
		}
#ifdef IDLE_THREADS
	}
	else {
		if (GloVars.global.idle_threads) {
			if (pthread_create(&pgsql_threads_idles[tn].thread_id, &attr, start_routine, &pgsql_threads_idles[tn]) != 0) {
				// LCOV_EXCL_START
				proxy_error("Thread creation\n");
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
#endif // IDLE_THREADS
	}
	return NULL;
}

void PgSQL_Threads_Handler::shutdown_threads() {
	unsigned int i;
	shutdown_ = 1;
	if (pgsql_threads) {
		for (i = 0; i < num_threads; i++) {
			if (pgsql_threads[i].worker) {
				pthread_mutex_lock(&pgsql_threads[i].worker->thread_mutex);
				pgsql_threads[i].worker->shutdown = 1;
				pthread_mutex_unlock(&pgsql_threads[i].worker->thread_mutex);
			}
		}
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads) {
			for (i = 0; i < num_threads; i++) {
				if (pgsql_threads_idles[i].worker) {
					pthread_mutex_lock(&pgsql_threads[i].worker->thread_mutex);
					pgsql_threads_idles[i].worker->shutdown = 1;
					pthread_mutex_unlock(&pgsql_threads[i].worker->thread_mutex);
				}
			}
		}
#endif /* IDLE_THREADS */
		signal_all_threads(1);
		for (i = 0; i < num_threads; i++) {
			if (pgsql_threads[i].worker)
				pthread_join(pgsql_threads[i].thread_id, NULL);
#ifdef IDLE_THREADS
			if (GloVars.global.idle_threads) {
				if (pgsql_threads_idles[i].worker)
					pthread_join(pgsql_threads_idles[i].thread_id, NULL);
			}
#endif /* IDLE_THREADS */
		}
	}
}

void PgSQL_Threads_Handler::start_listeners() {
	// we set bootstrapping_listeners to true
	// In this way PgSQL_Thread will knows there are more listeners to add
	// and it will continue looping until all listeners are added
	bootstrapping_listeners = true;
	char* _tmp = NULL;
	_tmp = GloPTH->get_variable((char*)"interfaces");
	if (strlen(_tmp) == 0) {
		GloPTH->set_variable((char*)"interfaces", (char*)"0.0.0.0:6133");
	}
	free(_tmp);
	tokenizer_t tok;
	tokenizer(&tok, variables.interfaces, ";", TOKENIZER_NO_EMPTIES);
	const char* token;
	for (token = tokenize(&tok); token; token = tokenize(&tok)) {
		listener_add((char*)token);
	}
	free_tokenizer(&tok);
	// no more listeners to add
	bootstrapping_listeners = false;
}

void PgSQL_Threads_Handler::stop_listeners() {
	if (variables.interfaces == NULL || strlen(variables.interfaces) == 0)
		return;
	tokenizer_t tok;
	tokenizer(&tok, variables.interfaces, ";", TOKENIZER_NO_EMPTIES);
	const char* token;
	for (token = tokenize(&tok); token; token = tokenize(&tok)) {
		listener_del((char*)token);
	}
	free_tokenizer(&tok);
}

/**
 * @brief Gets the client address stored in 'client_addr' member as
 *   an string if available. If member 'client_addr' is NULL, returns an
 *   empty string.
 *
 * @return Either an string holding the string representation of internal
 *   member 'client_addr', or empty string if this member is NULL.
 */
static std::string get_client_addr(struct sockaddr* client_addr) {
	char buf[INET6_ADDRSTRLEN];
	std::string str_client_addr{};

	if (client_addr == NULL) {
		return str_client_addr;
	}

	switch (client_addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)client_addr;
		inet_ntop(client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
		str_client_addr = std::string{ buf };
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)client_addr;
		inet_ntop(client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
		str_client_addr = std::string{ buf };
		break;
	}
	default:
		str_client_addr = std::string{ "localhost" };
		break;
	}

	return str_client_addr;
}

PgSQL_Client_Host_Cache_Entry PgSQL_Threads_Handler::find_client_host_cache(struct sockaddr* client_sockaddr) {
	PgSQL_Client_Host_Cache_Entry entry{ 0, 0 };
	// Client_sockaddr **shouldn't** ever by 'NULL', no matter the
	// 'session_type' in from which this function is called. Because
	// `PgSQL_Session::client_myds::client_addr` should **always** be
	// initialized before `handler` is called.
	assert(client_sockaddr != NULL);
	if (client_sockaddr->sa_family != AF_INET && client_sockaddr->sa_family != AF_INET6) {
		return entry;
	}
	std::string client_addr = get_client_addr(client_sockaddr);
	if (client_addr == "127.0.0.1") {
		return entry;
	}

	pthread_mutex_lock(&mutex_client_host_cache);
	auto found_entry = client_host_cache.find(client_addr);
	if (found_entry != client_host_cache.end()) {
		entry = found_entry->second;
	}
	pthread_mutex_unlock(&mutex_client_host_cache);

	return entry;
}

/**
 * @brief Number of columns for representing a 'PgSQL_Client_Host_Cache_Entry'
 *   in a 'SQLite3_result'.
 */
const int CLIENT_HOST_CACHE_COLUMNS = 3;

/**
 * @brief Helper function that converts a given client address and a
 *   'PgSQL_Client_Host_Cache_Entry', into a row for a 'SQLite3_result' for
 *   table 'STATS_SQLITE_TABLE_MYSQL_CLIENT_HOST_CACHE'.
 *
 * @param address The client address to be added to the resulset row.
 * @param entry The 'PgSQL_Client_Host_Cache_Entry' to be added to the resulset
 *   row.
 *
 * @return A pointer array holding the values for each of the columns of the
 *   row. It should be freed through helper function 'free_client_host_cache_row'.
 */
char** client_host_cache_entry_row(
	const std::string address, const PgSQL_Client_Host_Cache_Entry & entry
) {
	// INET6_ADDRSTRLEN length should be enough for holding any member:
	//  { address: MAX INET6_ADDRSTRLEN, updated_at: uint64_t, error_count: uint32_t }
	char buff[INET6_ADDRSTRLEN];
	char** row =
		static_cast<char**>(malloc(sizeof(char*) * CLIENT_HOST_CACHE_COLUMNS));

	time_t __now = time(NULL);
	unsigned long long curtime = monotonic_time();
	time_t last_updated = __now - curtime / 1000000 + entry.updated_at / 1000000;

	row[0] = strdup(address.c_str());
	sprintf(buff, "%u", entry.error_count);
	row[1] = strdup(buff);
	sprintf(buff, "%lu", last_updated);
	row[2] = strdup(buff);

	return row;
}

/**
 * @brief Helper function to free the row returned by
 * 'client_host_cache_entry_row'.
 *
 * @param row The pointer array holding the row values to be freed.
 */
static void free_client_host_cache_row(char** row) {
	for (int i = 0; i < CLIENT_HOST_CACHE_COLUMNS; i++) {
		free(row[i]);
	}
	free(row);
}

SQLite3_result* PgSQL_Threads_Handler::get_client_host_cache(bool reset) {
	SQLite3_result* result = new SQLite3_result(CLIENT_HOST_CACHE_COLUMNS);

	pthread_mutex_lock(&mutex_client_host_cache);
	result->add_column_definition(SQLITE_TEXT, "client_address");
	result->add_column_definition(SQLITE_TEXT, "error_count");
	result->add_column_definition(SQLITE_TEXT, "last_updated");

	for (const auto& cache_entry : client_host_cache) {
		char** row = client_host_cache_entry_row(cache_entry.first, cache_entry.second);
		result->add_row(row);
		free_client_host_cache_row(row);
	}

	if (reset) {
		client_host_cache.clear();
	}

	pthread_mutex_unlock(&mutex_client_host_cache);
	return result;
}

void PgSQL_Threads_Handler::update_client_host_cache(struct sockaddr* client_sockaddr, bool error) {
	// Client_sockaddr **shouldn't** ever by 'NULL', no matter the
	// 'session_type' in from which this function is called. Because
	// `PgSQL_Session::client_myds::client_addr` should **always** be
	// initialized before `handler` is called.
	assert(client_sockaddr != NULL);
	if (client_sockaddr->sa_family != AF_INET && client_sockaddr->sa_family != AF_INET6) {
		return;
	}
	std::string client_addr = get_client_addr(client_sockaddr);
	if (client_addr == "127.0.0.1") {
		return;
	}

	if (error) {
		pthread_mutex_lock(&mutex_client_host_cache);
		// If the cache is full, find the oldest entry on it, and update/remove it.
		if (
			pgsql_thread___client_host_cache_size &&
			client_host_cache.size() >= static_cast<size_t>(pgsql_thread___client_host_cache_size)
			) {
			auto older_elem = std::min_element(
				client_host_cache.begin(),
				client_host_cache.end(),
				[](const std::pair<std::string, PgSQL_Client_Host_Cache_Entry>& f_entry,
					const std::pair<std::string, PgSQL_Client_Host_Cache_Entry>& s_entry)
				{
					return f_entry.second.updated_at < s_entry.second.updated_at;
				}
			);
			if (older_elem != client_host_cache.end()) {
				if (older_elem->first != client_addr) {
					client_host_cache.erase(older_elem);
				}
			}
		}

		// Find the entry for the client, and update/insert it.
		auto cache_entry = client_host_cache.find(client_addr);
		if (cache_entry != client_host_cache.end()) {
			cache_entry->second.error_count += 1;
			cache_entry->second.updated_at = monotonic_time();
		}
		else {
			// Notice than the value of 'pgsql_thread___client_host_cache_size' can
			// change at runtime. Due to this, we should only insert when the size of the
			// cache is smaller than this value, otherwise we could end in situations in
			// which cache doesn't shrink after it's size is reduced at runtime.
			if (client_host_cache.size() < static_cast<size_t>(pgsql_thread___client_host_cache_size)) {
				PgSQL_Client_Host_Cache_Entry new_entry{ monotonic_time(), 1 };
				client_host_cache.insert({ client_addr, new_entry });
			}
		}
		pthread_mutex_unlock(&mutex_client_host_cache);
	}
	else {
		pthread_mutex_lock(&mutex_client_host_cache);
		client_host_cache.erase(client_addr);
		pthread_mutex_unlock(&mutex_client_host_cache);
	}
}

void PgSQL_Threads_Handler::flush_client_host_cache() {
	pthread_mutex_lock(&mutex_client_host_cache);
	client_host_cache.clear();
	pthread_mutex_unlock(&mutex_client_host_cache);
}

PgSQL_Threads_Handler::~PgSQL_Threads_Handler() {
	if (variables.monitor_username) { free(variables.monitor_username); variables.monitor_username = NULL; }
	if (variables.monitor_password) { free(variables.monitor_password); variables.monitor_password = NULL; }
	if (variables.monitor_replication_lag_use_percona_heartbeat) {
		free(variables.monitor_replication_lag_use_percona_heartbeat);
		variables.monitor_replication_lag_use_percona_heartbeat = NULL;
	}
	if (variables.default_schema) free(variables.default_schema);
	if (variables.interfaces) free(variables.interfaces);
	if (variables.server_version) free(variables.server_version);
	if (variables.default_client_encoding) free(variables.default_client_encoding);
	if (variables.keep_multiplexing_variables) free(variables.keep_multiplexing_variables);
	if (variables.firewall_whitelist_errormsg) free(variables.firewall_whitelist_errormsg);
	if (variables.init_connect) free(variables.init_connect);
	if (variables.ldap_user_variable) free(variables.ldap_user_variable);
	if (variables.add_ldap_user_comment) free(variables.add_ldap_user_comment);
	if (variables.default_session_track_gtids) free(variables.default_session_track_gtids);
	if (variables.eventslog_filename) free(variables.eventslog_filename);
	if (variables.auditlog_filename) free(variables.auditlog_filename);
	if (variables.ssl_p2s_ca) free(variables.ssl_p2s_ca);
	if (variables.ssl_p2s_capath) free(variables.ssl_p2s_capath);
	if (variables.ssl_p2s_cert) free(variables.ssl_p2s_cert);
	if (variables.ssl_p2s_key) free(variables.ssl_p2s_key);
	if (variables.ssl_p2s_cipher) free(variables.ssl_p2s_cipher);
	if (variables.ssl_p2s_crl) free(variables.ssl_p2s_crl);
	if (variables.ssl_p2s_crlpath) free(variables.ssl_p2s_crlpath);

	for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (variables.default_variables[i]) {
			free(variables.default_variables[i]);
			variables.default_variables[i] = NULL;
		}
	}
	free(pgsql_threads);
	pgsql_threads = NULL;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		free(pgsql_threads_idles);
		pgsql_threads_idles = NULL;
	}
#endif // IDLE_THREADS
	delete MLM;
	MLM = NULL;
}

PgSQL_Thread::~PgSQL_Thread() {

	if (mysql_sessions) {
		while (mysql_sessions->len) {
			PgSQL_Session* sess = (PgSQL_Session*)mysql_sessions->remove_index_fast(0);
			if (sess->session_type == PROXYSQL_SESSION_ADMIN || sess->session_type == PROXYSQL_SESSION_STATS) {
				char _buf[1024];
				sprintf(_buf, "%s:%d:%s()", __FILE__, __LINE__, __func__);
				if (GloPgSQL_Logger) { GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, sess, NULL, _buf); }
			}
			delete sess;
		}
		delete mysql_sessions;
		mysql_sessions = NULL;
		GloPgQPro->end_thread(); // only for real threads
	}

	if (mirror_queue_mysql_sessions) {
		while (mirror_queue_mysql_sessions->len) {
			PgSQL_Session* sess = (PgSQL_Session*)mirror_queue_mysql_sessions->remove_index_fast(0);
			delete sess;
		}
		delete mirror_queue_mysql_sessions;
		mirror_queue_mysql_sessions = NULL;
	}

	if (mirror_queue_mysql_sessions_cache) {
		while (mirror_queue_mysql_sessions_cache->len) {
			PgSQL_Session* sess = (PgSQL_Session*)mirror_queue_mysql_sessions_cache->remove_index_fast(0);
			delete sess;
		}
		delete mirror_queue_mysql_sessions_cache;
		mirror_queue_mysql_sessions_cache = NULL;
	}

#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		if (idle_mysql_sessions) {
			while (idle_mysql_sessions->len) {
				PgSQL_Session* sess = (PgSQL_Session*)idle_mysql_sessions->remove_index_fast(0);
				delete sess;
			}
			delete idle_mysql_sessions;
		}

		if (resume_mysql_sessions) {
			while (resume_mysql_sessions->len) {
				PgSQL_Session* sess = (PgSQL_Session*)resume_mysql_sessions->remove_index_fast(0);
				delete sess;
			}
			delete resume_mysql_sessions;
		}

		if (myexchange.idle_mysql_sessions) {
			while (myexchange.idle_mysql_sessions->len) {
				PgSQL_Session* sess = (PgSQL_Session*)myexchange.idle_mysql_sessions->remove_index_fast(0);
				delete sess;
			}
			delete myexchange.idle_mysql_sessions;
		}

		if (myexchange.resume_mysql_sessions) {
			while (myexchange.resume_mysql_sessions->len) {
				PgSQL_Session* sess = (PgSQL_Session*)myexchange.resume_mysql_sessions->remove_index_fast(0);
				delete sess;
			}
			delete myexchange.resume_mysql_sessions;
		}
	}
#endif // IDLE_THREADS

	if (cached_connections) {
		return_local_connections();
		delete cached_connections;
	}

	unsigned int i;
	for (i = 0; i < mypolls.len; i++) {
		if (
			mypolls.myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
			mypolls.myds[i]->myds_type == MYDS_LISTENER) {
			delete mypolls.myds[i];
		}
	}

	if (my_idle_conns)
		free(my_idle_conns);

	if (mysql_thread___monitor_username) { free(mysql_thread___monitor_username); mysql_thread___monitor_username = NULL; }
	if (mysql_thread___monitor_password) { free(mysql_thread___monitor_password); mysql_thread___monitor_password = NULL; }
	if (mysql_thread___monitor_replication_lag_use_percona_heartbeat) {
		free(mysql_thread___monitor_replication_lag_use_percona_heartbeat);
		mysql_thread___monitor_replication_lag_use_percona_heartbeat = NULL;
	}
	//if (pgsql_thread___default_schema) { free(pgsql_thread___default_schema); pgsql_thread___default_schema = NULL; }
	if (pgsql_thread___keep_multiplexing_variables) { free(pgsql_thread___keep_multiplexing_variables); pgsql_thread___keep_multiplexing_variables = NULL; }
	if (pgsql_thread___firewall_whitelist_errormsg) { free(pgsql_thread___firewall_whitelist_errormsg); pgsql_thread___firewall_whitelist_errormsg = NULL; }
	if (pgsql_thread___init_connect) { free(pgsql_thread___init_connect); pgsql_thread___init_connect = NULL; }
	//if (mysql_thread___ldap_user_variable) { free(mysql_thread___ldap_user_variable); mysql_thread___ldap_user_variable = NULL; }
	//if (mysql_thread___add_ldap_user_comment) { free(mysql_thread___add_ldap_user_comment); mysql_thread___add_ldap_user_comment = NULL; }
	//if (mysql_thread___default_session_track_gtids) { free(mysql_thread___default_session_track_gtids); mysql_thread___default_session_track_gtids = NULL; }
	
	if (pgsql_thread___server_version) { free(pgsql_thread___server_version); pgsql_thread___server_version = NULL; }
	if (pgsql_thread___default_client_encoding) { free(pgsql_thread___default_client_encoding); pgsql_thread___default_client_encoding = NULL; }

	for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (mysql_thread___default_variables[i]) {
			free(mysql_thread___default_variables[i]);
			mysql_thread___default_variables[i] = NULL;
		}
	}

	if (pgsql_thread___eventslog_filename) { free(pgsql_thread___eventslog_filename); pgsql_thread___eventslog_filename = NULL; }
	if (pgsql_thread___auditlog_filename) { free(pgsql_thread___auditlog_filename); pgsql_thread___auditlog_filename = NULL; }
	if (pgsql_thread___ssl_p2s_ca) { free(pgsql_thread___ssl_p2s_ca); pgsql_thread___ssl_p2s_ca = NULL; }
	if (pgsql_thread___ssl_p2s_capath) { free(pgsql_thread___ssl_p2s_capath); pgsql_thread___ssl_p2s_capath = NULL; }
	if (pgsql_thread___ssl_p2s_cert) { free(pgsql_thread___ssl_p2s_cert); pgsql_thread___ssl_p2s_cert = NULL; }
	if (pgsql_thread___ssl_p2s_key) { free(pgsql_thread___ssl_p2s_key); pgsql_thread___ssl_p2s_key = NULL; }
	if (pgsql_thread___ssl_p2s_cipher) { free(pgsql_thread___ssl_p2s_cipher); pgsql_thread___ssl_p2s_cipher = NULL; }
	if (pgsql_thread___ssl_p2s_crl) { free(pgsql_thread___ssl_p2s_crl); pgsql_thread___ssl_p2s_crl = NULL; }
	if (pgsql_thread___ssl_p2s_crlpath) { free(pgsql_thread___ssl_p2s_crlpath); pgsql_thread___ssl_p2s_crlpath = NULL; }

	if (match_regexes) {
		Session_Regex* sr = NULL;
		sr = match_regexes[0];
		delete sr;
		sr = match_regexes[1];
		delete sr;
		sr = match_regexes[2];
		delete sr;
		sr = match_regexes[3];
		delete sr;
		free(match_regexes);
		match_regexes = NULL;
	}
	if (thr_SetParser != NULL) {
		delete thr_SetParser;
		thr_SetParser = NULL;
	}

}

bool PgSQL_Thread::init() {
	int i;
	mysql_sessions = new PtrArray();
	mirror_queue_mysql_sessions = new PtrArray();
	mirror_queue_mysql_sessions_cache = new PtrArray();
	cached_connections = new PtrArray();
	assert(mysql_sessions);

#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		idle_mysql_sessions = new PtrArray();
		resume_mysql_sessions = new PtrArray();

		myexchange.idle_mysql_sessions = new PtrArray();
		myexchange.resume_mysql_sessions = new PtrArray();
		pthread_mutex_init(&myexchange.mutex_idles, NULL);
		pthread_mutex_init(&myexchange.mutex_resumes, NULL);
		assert(idle_mysql_sessions);
		assert(resume_mysql_sessions);
	}
#endif // IDLE_THREADS

	pthread_mutex_init(&kq.m, NULL);

	shutdown = 0;
	my_idle_conns = (PgSQL_Connection**)malloc(sizeof(PgSQL_Connection*) * SESSIONS_FOR_CONNECTIONS_HANDLER);
	memset(my_idle_conns, 0, sizeof(PgSQL_Connection*) * SESSIONS_FOR_CONNECTIONS_HANDLER);
	GloPgQPro->init_thread();
	refresh_variables();
	i = pipe(pipefd);
	ioctl_FIONBIO(pipefd[0], 1);
	ioctl_FIONBIO(pipefd[1], 1);
	mypolls.add(POLLIN, pipefd[0], NULL, 0);
	assert(i == 0);

	thr_SetParser = new SetParser("");
	match_regexes = (Session_Regex**)malloc(sizeof(Session_Regex*) * 4);
	//	match_regexes[0]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)SQL_LOG_BIN( *)(:|)=( *)");
	match_regexes[0] = NULL; // NOTE: historically we used match_regexes[0] for SET SQL_LOG_BIN . Not anymore

	std::stringstream ss;
	ss << "^SET (|SESSION |@@|@@session.|@@local.)`?(" << pgsql_variables.variables_regexp << "SESSION_TRACK_GTIDS|TX_ISOLATION|TX_READ_ONLY|TRANSACTION_ISOLATION|TRANSACTION_READ_ONLY)`?( *)(:|)=( *)";
	match_regexes[1] = new Session_Regex((char*)ss.str().c_str());

	match_regexes[2] = new Session_Regex((char*)"^SET(?: +)(|SESSION +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))");
	match_regexes[3] = new Session_Regex((char*)"^(set)(?: +)((charset)|(character +set))(?: )");

	return true;
}

struct pollfd* PgSQL_Thread::get_pollfd(unsigned int i) {
	return &mypolls.fds[i];
}

void PgSQL_Thread::poll_listener_add(int sock) {
	PgSQL_Data_Stream* listener_DS = new PgSQL_Data_Stream();
	listener_DS->myds_type = MYDS_LISTENER;
	listener_DS->fd = sock;

	proxy_debug(PROXY_DEBUG_NET, 1, "Created listener %p for socket %d\n", listener_DS, sock);
	mypolls.add(POLLIN, sock, listener_DS, monotonic_time());
}

void PgSQL_Thread::poll_listener_del(int sock) {
	int i = mypolls.find_index(sock);
	if (i >= 0) {
		PgSQL_Data_Stream* myds = mypolls.myds[i];
		mypolls.remove_index_fast(i);
#ifdef SO_REUSEPORT
		if (GloVars.global.reuseport)
#else
		myds->fd = -1;	// this to prevent that delete myds will shutdown the fd;
#endif
		delete myds;
	}
}

void PgSQL_Thread::unregister_session(int idx) {
	if (mysql_sessions == NULL) return;
	proxy_debug(PROXY_DEBUG_NET, 1, "Thread=%p, Session=%p -- Unregistered session\n", this, mysql_sessions->index(idx));
	mysql_sessions->remove_index_fast(idx);
}


// this function was inline in PgSQL_Thread::run()
void PgSQL_Thread::run___get_multiple_idle_connections(int& num_idles) {
	int i;
	num_idles = PgHGM->get_multiple_idle_connections(-1, curtime - pgsql_thread___ping_interval_server_msec * 1000, my_idle_conns, SESSIONS_FOR_CONNECTIONS_HANDLER);
	for (i = 0; i < num_idles; i++) {
		PgSQL_Data_Stream* myds;
		PgSQL_Connection* mc = my_idle_conns[i];
		PgSQL_Session* sess = new PgSQL_Session();
		sess->mybe = sess->find_or_create_backend(mc->parent->myhgc->hid);

		myds = sess->mybe->server_myds;
		myds->attach_connection(mc);
		myds->assign_fd_from_mysql_conn();
		myds->myds_type = MYDS_BACKEND;

		sess->to_process = 1;
		myds->wait_until = curtime + pgsql_thread___ping_timeout_server * 1000;	// max_timeout
		mc->last_time_used = curtime;
		myds->myprot.init(&myds, myds->myconn->userinfo, NULL);
		sess->status = PINGING_SERVER;
		myds->DSS = STATE_MARIADB_PING;
		register_session_connection_handler(sess, true);
		int rc = sess->handler();
		if (rc == -1) {
			unsigned int sess_idx = mysql_sessions->len - 1;
			unregister_session(sess_idx);
			delete sess;
		}
	}
	processing_idles = true;
	last_processing_idles = curtime;
}

// this function was inline in PgSQL_Thread::run()
void PgSQL_Thread::run___cleanup_mirror_queue() {
	unsigned int l = (unsigned int)pgsql_thread___mirror_max_concurrency;
	if (mirror_queue_mysql_sessions_cache->len > l) {
		while (mirror_queue_mysql_sessions_cache->len > mirror_queue_mysql_sessions->len && mirror_queue_mysql_sessions_cache->len > l) {
			PgSQL_Session* newsess = (PgSQL_Session*)mirror_queue_mysql_sessions_cache->remove_index_fast(0);
			__sync_add_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
			//GloPTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Increment();
			delete newsess;
		}
	}
}

// main loop
void PgSQL_Thread::run() {
	unsigned int n;
	int rc;

#ifdef IDLE_THREADS
	bool idle_maintenance_thread = epoll_thread;
	if (idle_maintenance_thread) {
		// we check if it is the first time we are called
		if (efd == -1) {
			efd = EPOLL_CREATE;
			int fd = pipefd[0];
			struct epoll_event event;
			memset(&event, 0, sizeof(event)); // let's make valgrind happy
			event.events = EPOLLIN;
			event.data.u32 = 0; // special value to point to the pipe
			epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		}
	}
#endif // IDLE_THREADS

	curtime = monotonic_time();
	atomic_curtime = curtime;

	pthread_mutex_lock(&thread_mutex);
	while (shutdown == 0) {

#ifdef IDLE_THREADS
		if (idle_maintenance_thread) {
			goto __run_skip_1;
		}
#endif // IDLE_THREADS

		int num_idles;
		if (processing_idles == true && (last_processing_idles < curtime - pgsql_thread___ping_timeout_server * 1000)) {
			processing_idles = false;
		}
		if (processing_idles == false && (last_processing_idles < curtime - pgsql_thread___ping_interval_server_msec * 1000)) {
			run___get_multiple_idle_connections(num_idles);
		}

#ifdef IDLE_THREADS
		__run_skip_1 :

		if (idle_maintenance_thread) {
			idle_thread_gets_sessions_from_worker_thread();
			goto __run_skip_1a;
		}
#endif // IDLE_THREADS

		handle_mirror_queue_mysql_sessions();

		ProcessAllMyDS_BeforePoll<PgSQL_Thread>();

#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads) {
			if (idle_maintenance_thread == false) {
				int r = rand() % (GloPTH->num_threads);
				PgSQL_Thread* thr = GloPTH->pgsql_threads_idles[r].worker;
				worker_thread_assigns_sessions_to_idle_thread(thr);
				worker_thread_gets_sessions_from_idle_thread();
			}
		}


	__run_skip_1a:
#endif // IDLE_THREADS

		pthread_mutex_unlock(&thread_mutex);
		if (unlikely(mypolls.bootstrapping_listeners == true)) {
			while ( // spin here if ...
				(n = __sync_add_and_fetch(&mypolls.pending_listener_add, 0)) // there is a new listener to add
				||
				(GloPTH->bootstrapping_listeners == true) // PgSQL_Thread_Handlers has more listeners to configure
				) {
				if (n) {
					poll_listener_add(n);
					assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_add, n, 0));
				}
				else {
					if (GloPTH->bootstrapping_listeners == false) {
						// we stop looping
						mypolls.bootstrapping_listeners = false;
					}
				}
#ifdef DEBUG
				usleep(5 + rand() % 10);
#endif
			}
		}

		proxy_debug(PROXY_DEBUG_NET, 7, "poll_timeout=%u\n", mypolls.poll_timeout);
		if (pgsql_thread___wait_timeout == 0) {
			// we should be going into PAUSE mode
			if (mypolls.poll_timeout == 0 || mypolls.poll_timeout > 100000) {
				mypolls.poll_timeout = 100000;
			}
		}
		proxy_debug(PROXY_DEBUG_NET, 7, "poll_timeout=%u\n", mypolls.poll_timeout);


		// flush mysql log file
		GloPgSQL_Logger->flush();

		pre_poll_time = curtime;
		int ttw = (mypolls.poll_timeout ? (mypolls.poll_timeout / 1000 < (unsigned int)pgsql_thread___poll_timeout ? mypolls.poll_timeout / 1000 : pgsql_thread___poll_timeout) : pgsql_thread___poll_timeout);
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			memset(events, 0, sizeof(struct epoll_event) * MY_EPOLL_THREAD_MAXEVENTS); // let's make valgrind happy. It also seems that needs to be zeroed anyway
			// we call epoll()
			rc = epoll_wait(efd, events, MY_EPOLL_THREAD_MAXEVENTS, pgsql_thread___poll_timeout);
		}
		else {
#endif // IDLE_THREADS
			//this is the only portion of code not protected by a global mutex
			proxy_debug(PROXY_DEBUG_NET, 5, "Calling poll with timeout %d\n", ttw);
			// poll is called with a timeout of mypolls.poll_timeout if set , or pgsql_thread___poll_timeout
			rc = poll(mypolls.fds, mypolls.len, ttw);
			proxy_debug(PROXY_DEBUG_NET, 5, "%s\n", "Returning poll");
#ifdef IDLE_THREADS
		}
#endif // IDLE_THREADS

		if (unlikely(maintenance_loop == true)) {
			while ((n = __sync_add_and_fetch(&mypolls.pending_listener_del, 0))) {	// spin here
				if (static_cast<int>(n) == -1) {
					for (unsigned int i = 0; i < mypolls.len; i++) {
						if (mypolls.myds[i] && mypolls.myds[i]->myds_type == MYDS_LISTENER) {
							poll_listener_del(mypolls.myds[i]->fd);
						}
					}
				}
				else {
					poll_listener_del(n);
				}
				assert(__sync_bool_compare_and_swap(&mypolls.pending_listener_del, n, 0));
			}
		}

		pthread_mutex_lock(&thread_mutex);
		if (shutdown == 1) { return; }
		mypolls.poll_timeout = 0; // always reset this to 0 . If a session needs a specific timeout, it will set this one

		curtime = monotonic_time();
		atomic_curtime = curtime;

		poll_timeout_bool = false;
		if (
#ifdef IDLE_THREADS
			idle_maintenance_thread == false &&
#endif // IDLE_THREADS
			(curtime >= (pre_poll_time + ttw))) {
			poll_timeout_bool = true;
		}
		unsigned long long maintenance_interval = 1000000; // hardcoded value for now
#ifdef IDLE_THREADS
		if (idle_maintenance_thread) {
			maintenance_interval = maintenance_interval * 2;
		}
#endif // IDLE_THREADS
		if (curtime > last_maintenance_time + maintenance_interval) {
			last_maintenance_time = curtime;
			maintenance_loop = true;
			servers_table_version_previous = servers_table_version_current;
			servers_table_version_current = PgHGM->get_servers_table_version();
		}
		else {
			maintenance_loop = false;
		}

		handle_kill_queues();

		// update polls statistics
		mypolls.loops++;
		mypolls.loop_counters->incr(curtime / 1000000);

		if (maintenance_loop == true
#ifdef IDLE_THREADS
			// in case of idle thread
			// do not run any mirror cleanup and do not
			// update query processor stats
			&& idle_maintenance_thread == false
#endif // IDLE_THREADS
			) {
			// house keeping
			run___cleanup_mirror_queue();
			GloPgQPro->update_query_processor_stats();
		}

		if (rc == -1 && errno == EINTR)
			// poll() timeout, try again
			continue;
		if (rc == -1) {
			// LCOV_EXCL_START
				// error , exit
			perror("poll()");
			exit(EXIT_FAILURE);
			// LCOV_EXCL_STOP
		}

		if (__sync_add_and_fetch(&__global_PgSQL_Thread_Variables_version, 0) > __thread_PgSQL_Thread_Variables_version) {
			refresh_variables();
		}

		run_SetAllSession_ToProcess0<PgSQL_Thread,PgSQL_Session>();

#ifdef IDLE_THREADS
		// here we handle epoll_wait()
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			if (rc) {
				int i;
				for (i = 0; i < rc; i++) {
					if (events[i].data.u32) {
						idle_thread_prepares_session_to_send_to_worker_thread(i);
					}
				}
				// FIXME: this loop seems suboptimal, it can be combined with the previous one
				for (i = 0; i < rc; i++) {
					if (events[i].events == EPOLLIN && events[i].data.u32 == 0) {
						unsigned char c;
						int fd = pipefd[0];
						if (read(fd, &c, 1) <= 0) {
						}
						else {
							//i=rc;
							maintenance_loop = true;
						}
					}
				}
			}
			if (mysql_sessions->len && maintenance_loop) {
				if (curtime == last_maintenance_time) {
					idle_thread_to_kill_idle_sessions();
				}
			}
			goto __run_skip_2;
		}
#endif // IDLE_THREADS

		ProcessAllMyDS_AfterPoll<PgSQL_Thread>();

#ifdef IDLE_THREADS
		__run_skip_2 :
		if (GloVars.global.idle_threads && idle_maintenance_thread) {
			// this is an idle thread
			unsigned int w = rand() % (GloPTH->num_threads);
			PgSQL_Thread* thr = GloPTH->pgsql_threads[w].worker;
			if (resume_mysql_sessions->len) {
				idle_thread_assigns_sessions_to_worker_thread(thr);
			}
			else {
				idle_thread_check_if_worker_thread_has_unprocess_resumed_sessions_and_signal_it(thr);
			}
		}
		else {
#endif // IDLE_THREADS
			// iterate through all sessions and process the session logic
			process_all_sessions();

			return_local_connections();
#ifdef IDLE_THREADS
		}
#endif // IDLE_THREADS
	}
}
// end of ::run()

#ifdef IDLE_THREADS
void PgSQL_Thread::idle_thread_to_kill_idle_sessions() {
#define	SESS_TO_SCAN	128
	if (mysess_idx + SESS_TO_SCAN > mysql_sessions->len) {
		mysess_idx = 0;
	}
	unsigned int i;
	unsigned long long min_idle = 0;
	if (curtime > (unsigned long long)pgsql_thread___wait_timeout * 1000) {
		min_idle = curtime - (unsigned long long)pgsql_thread___wait_timeout * 1000;
	}
	for (i = 0; i < SESS_TO_SCAN && mysess_idx < mysql_sessions->len; i++) {
		uint32_t sess_pos = mysess_idx;
		PgSQL_Session* mysess = (PgSQL_Session*)mysql_sessions->index(sess_pos);
		if (mysess->idle_since < min_idle || mysess->killed == true) {
			mysess->killed = true;
			PgSQL_Data_Stream* tmp_myds = mysess->client_myds;
			int dsidx = tmp_myds->poll_fds_idx;
			//fprintf(stderr,"Removing session %p, DS %p idx %d\n",mysess,tmp_myds,dsidx);
			mypolls.remove_index_fast(dsidx);
			tmp_myds->mypolls = NULL;
			mysess->thread = NULL;
			// we first delete the association in sessmap
			sessmap.erase(mysess->thread_session_id);
			if (mysql_sessions->len > 1) {
				// take the last element and adjust the map
				PgSQL_Session* mysess_last = (PgSQL_Session*)mysql_sessions->index(mysql_sessions->len - 1);
				if (mysess->thread_session_id != mysess_last->thread_session_id)
					sessmap[mysess_last->thread_session_id] = sess_pos;
			}
			unregister_session(sess_pos);
			resume_mysql_sessions->add(mysess);
			epoll_ctl(efd, EPOLL_CTL_DEL, tmp_myds->fd, NULL);
		}
		mysess_idx++;
	}
}

void PgSQL_Thread::idle_thread_prepares_session_to_send_to_worker_thread(int i) {
	// NOTE: not sure why, sometime events returns odd values. If set, we take it out as normal worker threads know how to handle it
	if (events[i].events) {
		uint32_t sess_thr_id = events[i].data.u32;
		uint32_t sess_pos = sessmap[sess_thr_id];
		PgSQL_Session* mysess = (PgSQL_Session*)mysql_sessions->index(sess_pos);
		PgSQL_Data_Stream* tmp_myds = mysess->client_myds;
		int dsidx = tmp_myds->poll_fds_idx;
		//fprintf(stderr,"Removing session %p, DS %p idx %d\n",mysess,tmp_myds,dsidx);
		mypolls.remove_index_fast(dsidx);
		tmp_myds->mypolls = NULL;
		mysess->thread = NULL;
		// we first delete the association in sessmap
		sessmap.erase(mysess->thread_session_id);
		if (mysql_sessions->len > 1) {
			// take the last element and adjust the map
			PgSQL_Session* mysess_last = (PgSQL_Session*)mysql_sessions->index(mysql_sessions->len - 1);
			if (mysess->thread_session_id != mysess_last->thread_session_id)
				sessmap[mysess_last->thread_session_id] = sess_pos;
		}
		unregister_session(sess_pos);
		resume_mysql_sessions->add(mysess);
		epoll_ctl(efd, EPOLL_CTL_DEL, tmp_myds->fd, NULL);
	}
}

void PgSQL_Thread::idle_thread_check_if_worker_thread_has_unprocess_resumed_sessions_and_signal_it(PgSQL_Thread * thr) {
	pthread_mutex_lock(&thr->myexchange.mutex_resumes);
	if (shutdown == 0 && thr->shutdown == 0 && thr->myexchange.resume_mysql_sessions->len) {
		unsigned char c = 0;
		int fd = thr->pipefd[1];
		if (write(fd, &c, 1) == -1) {
			//proxy_error("Error while signaling maintenance thread\n");
		}
	}
	pthread_mutex_unlock(&thr->myexchange.mutex_resumes);
}

void PgSQL_Thread::idle_thread_assigns_sessions_to_worker_thread(PgSQL_Thread * thr) {
	bool send_signal = false;
	// send_signal variable will control if we need to signal or not
	// the worker thread
	pthread_mutex_lock(&thr->myexchange.mutex_resumes);
	if (shutdown == 0 && thr->shutdown == 0)
		if (resume_mysql_sessions->len) {
			while (resume_mysql_sessions->len) {
				PgSQL_Session* mysess = (PgSQL_Session*)resume_mysql_sessions->remove_index_fast(0);
				thr->myexchange.resume_mysql_sessions->add(mysess);
			}
			send_signal = true; // signal only if there are sessions to resume
		}
	pthread_mutex_unlock(&thr->myexchange.mutex_resumes);
	if (send_signal) { // signal only if there are sessions to resume
		unsigned char c = 0;
		//PgSQL_Thread *thr=GloPTH->pgsql_threads[w].worker;
		// we signal the thread to inform there are sessions
		int fd = thr->pipefd[1];
		if (write(fd, &c, 1) == -1) {
			//proxy_error("Error while signaling maintenance thread\n");
		}
	}
}

void PgSQL_Thread::worker_thread_assigns_sessions_to_idle_thread(PgSQL_Thread * thr) {
	if (shutdown == 0 && thr->shutdown == 0 && idle_mysql_sessions->len) {
		pthread_mutex_lock(&thr->myexchange.mutex_idles);
		bool empty_queue = true;
		if (thr->myexchange.idle_mysql_sessions->len) {
			// there are already sessions in the queues. We assume someone already notified worker 0
			empty_queue = false;
		}
		while (idle_mysql_sessions->len) {
			PgSQL_Session* mysess = (PgSQL_Session*)idle_mysql_sessions->remove_index_fast(0);
			thr->myexchange.idle_mysql_sessions->add(mysess);
		}
		pthread_mutex_unlock(&thr->myexchange.mutex_idles);
		if (empty_queue == true) {
			unsigned char c = 1;
			int fd = thr->pipefd[1];
			if (write(fd, &c, 1) == -1) {
				//proxy_error("Error while signaling maintenance thread\n");
			}
		}
	}
}

void PgSQL_Thread::worker_thread_gets_sessions_from_idle_thread() {
	pthread_mutex_lock(&myexchange.mutex_resumes);
	if (myexchange.resume_mysql_sessions->len) {
		//unsigned int maxsess=GloPTH->resume_mysql_sessions->len;
		while (myexchange.resume_mysql_sessions->len) {
			PgSQL_Session* mysess = (PgSQL_Session*)myexchange.resume_mysql_sessions->remove_index_fast(0);
			register_session(this, mysess, false);
			PgSQL_Data_Stream* myds = mysess->client_myds;
			mypolls.add(POLLIN, myds->fd, myds, monotonic_time());
		}
	}
	pthread_mutex_unlock(&myexchange.mutex_resumes);
}
#endif // IDLE_THREADS


bool PgSQL_Thread::process_data_on_data_stream(PgSQL_Data_Stream * myds, unsigned int n) {
	if (mypolls.fds[n].revents) {
#ifdef IDLE_THREADS
		if (myds->myds_type == MYDS_FRONTEND) {
			if (epoll_thread) {
				mypolls.remove_index_fast(n);
				myds->mypolls = NULL;
				unsigned int i;
				for (i = 0; i < mysql_sessions->len; i++) {
					PgSQL_Session* mysess = (PgSQL_Session*)mysql_sessions->index(i);
					if (mysess == myds->sess) {
						mysess->thread = NULL;
						unregister_session(i);
						//exit_cond=true;
						resume_mysql_sessions->add(myds->sess);
						return false;
					}
				}
			}
		}
#endif // IDLE_THREADS
		mypolls.last_recv[n] = curtime;
		myds->revents = mypolls.fds[n].revents;
		myds->sess->to_process = 1;
		assert(myds->sess->status != session_status___NONE);
	}
	else {
		// no events
		if (myds->wait_until && curtime > myds->wait_until) {
			// timeout
			myds->sess->to_process = 1;
			assert(myds->sess->status != session_status___NONE);
		}
		else {
			if (myds->sess->pause_until && curtime > myds->sess->pause_until) {
				// timeout
				myds->sess->to_process = 1;
			}
		}
	}
	if (myds->myds_type == MYDS_BACKEND && myds->sess->status != FAST_FORWARD) {
		if (mypolls.fds[n].revents) {
			// this part of the code fixes an important bug
			// if a connection in use but idle (ex: running a transaction)
			// get data, immediately destroy the session
			//
			// this can happen, for example, with a low wait_timeout and running transaction
			if (myds->sess->status == WAITING_CLIENT_DATA) {
				if (myds->myconn->async_state_machine == ASYNC_IDLE) {
					proxy_warning("Detected broken idle connection on %s:%d\n", myds->myconn->parent->address, myds->myconn->parent->port);
					myds->destroy_MySQL_Connection_From_Pool(false);
					myds->sess->set_unhealthy();
					return false;
				}
			}
		}
		return true;
	}
	if (mypolls.fds[n].revents) {
		if (mypolls.myds[n]->DSS < STATE_MARIADB_BEGIN || mypolls.myds[n]->DSS > STATE_MARIADB_END) {
			// only if we aren't using MariaDB Client Library
			int rb = 0;
			do {
				rb = myds->read_from_net();
				if (rb > 0 && myds->myds_type == MYDS_FRONTEND) {
					status_variables.stvar[st_var_queries_frontends_bytes_recv] += rb;
				}
				myds->read_pkts();

				if (rb > 0 && myds->myds_type == MYDS_BACKEND) {
					if (myds->sess->session_fast_forward) {
						if (myds->encrypted == true) { // we are in fast_forward mode and encrypted == true
							// PMC-10004
							// we probably should use SSL_pending() and/or SSL_has_pending() to determine
							// if there is more data to be read, but it doesn't seem to be working.
							// Therefore we try to call read_from_net() again as long as there is data.
							// Previously we hardcoded 16KB but it seems that it can return in smaller
							// chunks of 4KB.
							// We finally removed the chunk size as it seems that any size is possible.
/*
										int sslp = SSL_pending(myds->ssl);
										int sslhp = SSL_has_pending(myds->ssl);
										proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p: in fast_forward mode and SSL read %d bytes , SSL_pending: %d bytes , SSL_has_pending: %d\n", myds->sess, rb, sslp, sslhp);
*/
							proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, DataStream=%p , thread_session_id=%u -- in fast_forward mode and SSL read %d bytes\n", myds->sess, myds, myds->sess->thread_session_id, rb);
							while (rb > 0) {
								rb = myds->read_from_net();
								if (rb > 0 && myds->myds_type == MYDS_FRONTEND) {
									status_variables.stvar[st_var_queries_frontends_bytes_recv] += rb;
								}
								proxy_debug(PROXY_DEBUG_NET, 5, "Session=%p, DataStream=%p -- in fast_forward mode and SSL read %d bytes\n", myds->sess, myds, rb);
								myds->read_pkts();
							}
							rb = 0; // exit loop
						}
						else { // we are in fast_forward mode and encrypted == false
							struct pollfd _fds;
							nfds_t _nfds = 1;
							_fds.fd = mypolls.fds[n].fd;
							_fds.events = POLLIN;
							_fds.revents = 0;
							int _rc = poll(&_fds, _nfds, 0);
							if ((_rc > 0) && _fds.revents == POLLIN) {
								// there is more data
								myds->revents = _fds.revents;
							}
							else {
								rb = 0; // exit loop
							}
						}
					}
					else {
						rb = 0; // exit loop
					}
				}
				else {
					bool set_rb_zero = true;
					if (rb > 0 && myds->myds_type == MYDS_FRONTEND) {
						if (myds->encrypted == true) {
							if (SSL_is_init_finished(myds->ssl)) {
								if (myds->data_in_rbio()) {
									set_rb_zero = false;
								}
							}
						}
					}
					if (set_rb_zero)
						rb = 0; // exit loop
				}
			} while (rb > 0);

		}
		else {
			if (mypolls.fds[n].revents) {
				myds->myconn->handler(mypolls.fds[n].revents);
			}
		}
		if ((mypolls.fds[n].events & POLLOUT)
			&&
			((mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP))
			) {
			myds->set_net_failure();
		}
		myds->check_data_flow();
	}


	if (myds->active == 0) {
		if (myds->sess->client_myds == myds) {
			proxy_debug(PROXY_DEBUG_NET, 1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
			myds->sess->set_unhealthy();
		}
		else {
			// if this is a backend with fast_forward, set unhealthy
			// if this is a backend without fast_forward, do not set unhealthy: it will be handled by client library
			if (myds->sess->session_fast_forward) { // if fast forward
				if (myds->myds_type == MYDS_BACKEND) { // and backend
					myds->sess->set_unhealthy(); // set unhealthy
				}
			}
		}
	}
	return true;
}


// this function was inline in PgSQL_Thread::process_all_sessions()
void PgSQL_Thread::ProcessAllSessions_CompletedMirrorSession(unsigned int& n, PgSQL_Session * sess) {
	unregister_session(n);
	n--;
	unsigned int l = (unsigned int)pgsql_thread___mirror_max_concurrency;
	if (mirror_queue_mysql_sessions->len * 0.3 > l) l = mirror_queue_mysql_sessions->len * 0.3;
	if (mirror_queue_mysql_sessions_cache->len <= l) {
		bool to_cache = true;
		if (sess->mybe) {
			if (sess->mybe->server_myds) {
				to_cache = false;
			}
		}
		if (to_cache) {
			__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
			//GloPTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
			mirror_queue_mysql_sessions_cache->add(sess);
		}
		else {
			delete sess;
		}
	}
	else {
		delete sess;
	}
}


// this function was inline in PgSQL_Thread::process_all_sessions()
void PgSQL_Thread::ProcessAllSessions_MaintenanceLoop(PgSQL_Session * sess, unsigned long long sess_time, unsigned int& total_active_transactions_) {
	unsigned int numTrx = 0;
	total_active_transactions_ += sess->active_transactions;
	sess->to_process = 1;
	if ((sess_time / 1000 > (unsigned long long)pgsql_thread___max_transaction_idle_time) || (sess_time / 1000 > (unsigned long long)pgsql_thread___wait_timeout)) {
		//numTrx = sess->NumActiveTransactions();
		numTrx = sess->active_transactions;
		if (numTrx) {
			// the session has idle transactions, kill it
			if (sess_time / 1000 > (unsigned long long)pgsql_thread___max_transaction_idle_time) {
				sess->killed = true;
				if (sess->client_myds) {
					proxy_warning("Killing client connection %s:%d because of (possible) transaction idle for %llums\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, sess_time / 1000);
				}
			}
		}
		else {
			// the session is idle, kill it
			if (sess_time / 1000 > (unsigned long long)pgsql_thread___wait_timeout) {
				sess->killed = true;
				if (sess->client_myds) {
					proxy_warning("Killing client connection %s:%d because inactive for %llums\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, sess_time / 1000);
				}
			}
		}
	}
	else {
		if (sess->active_transactions > 0) {
			// here is all the logic related to max_transaction_time
			unsigned long long trx_started = sess->transaction_started_at;
			if (trx_started > 0 && curtime > trx_started) {
				unsigned long long trx_time = curtime - trx_started;
				unsigned long long trx_time_ms = trx_time / 1000;
				if (trx_time_ms > (unsigned long long)pgsql_thread___max_transaction_time) {
					sess->killed = true;
					if (sess->client_myds) {
						proxy_warning("Killing client connection %s:%d because of (possible) transaction running for %llums\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, trx_time_ms);
					}
				}
			}
		}
	}
	if (servers_table_version_current != servers_table_version_previous) { // bug fix for #1085
		// Immediatelly kill all client connections using an OFFLINE node when session_fast_forward == true
		if (sess->session_fast_forward) {
			if (sess->HasOfflineBackends()) {
				sess->killed = true;
				proxy_warning("Killing client connection %s:%d due to 'session_fast_forward' and offline backends\n", sess->client_myds->addr.addr, sess->client_myds->addr.port);
			}
		}
		else {
			// Search for connections that should be terminated, and simulate data in them
			// the following 2 lines of code replace the previous 2 lines
			// instead of killing the sessions, fails the backend connections
			if (sess->SetEventInOfflineBackends()) {
				sess->to_process = 1;
			}
		}
	}

	// Perform the maintenance for expired connections on the session
	if (pgsql_thread___multiplexing) {
		const auto auto_incr_delay_multiplex_check = [curtime = this->curtime](PgSQL_Connection* myconn) -> bool {
			const uint64_t multiplex_timeout_ms = pgsql_thread___auto_increment_delay_multiplex_timeout_ms;
			const bool multiplex_delayed_enabled = multiplex_timeout_ms != 0 && myconn->auto_increment_delay_token > 0;
			const bool timeout_expired = multiplex_delayed_enabled && myconn->myds->wait_until != 0 && myconn->myds->wait_until < curtime;
			return timeout_expired;
			};

		const auto conn_delay_multiplex = [curtime = this->curtime](PgSQL_Connection* myconn) -> bool {
			const bool multiplex_delayed = pgsql_thread___connection_delay_multiplex_ms != 0 && myconn->multiplex_delayed == true;
			const bool timeout_expired = multiplex_delayed && myconn->myds->wait_until != 0 && myconn->myds->wait_until < curtime;
			return timeout_expired;
			};

		const vector<function<bool(PgSQL_Connection*)>> expire_conn_checks{
			auto_incr_delay_multiplex_check,
			conn_delay_multiplex
		};

		sess->update_expired_conns(expire_conn_checks);
	}
}

void PgSQL_Thread::process_all_sessions() {
	unsigned int n;
	unsigned int total_active_transactions_ = 0;
#ifdef IDLE_THREADS
	bool idle_maintenance_thread = epoll_thread;
#endif // IDLE_THREADS
	int rc;
	bool sess_sort = pgsql_thread___sessions_sort;
#ifdef IDLE_THREADS
	if (idle_maintenance_thread) {
		sess_sort = false;
	}
#endif // IDLE_THREADS
	if (sess_sort && mysql_sessions->len > 3) {
		ProcessAllSessions_SortingSessions<PgSQL_Session>();
	}
	for (n = 0; n < mysql_sessions->len; n++) {
		PgSQL_Session* sess = (PgSQL_Session*)mysql_sessions->index(n);
#ifdef DEBUG
		if (sess == sess_stopat) {
			sess_stopat = sess;
		}
#endif
		if (sess->mirror == true) { // this is a mirror session
			if (sess->status == WAITING_CLIENT_DATA) { // the mirror session has completed
				ProcessAllSessions_CompletedMirrorSession(n, sess);
				continue;
			}
		}
		if (sess->status == CONNECTING_CLIENT) {
			unsigned long long sess_time = sess->IdleTime();
			if (sess_time / 1000 > (unsigned long long)pgsql_thread___connect_timeout_client) {
				proxy_warning("Closing not established client connection %s:%d after %llums\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, sess_time / 1000);
				sess->healthy = 0;
				if (pgsql_thread___client_host_cache_size) {
					GloPTH->update_client_host_cache(sess->client_myds->client_addr, true);
				}
			}
		}
		if (maintenance_loop) {
			unsigned long long sess_time = sess->IdleTime();
#ifdef IDLE_THREADS
			if (idle_maintenance_thread == false)
#endif // IDLE_THREADS
			{
				ProcessAllSessions_MaintenanceLoop(sess, sess_time, total_active_transactions_);
			}
#ifdef IDLE_THREADS
			else
			{
				if ((sess_time / 1000 > (unsigned long long)pgsql_thread___wait_timeout)) {
					sess->killed = true;
					sess->to_process = 1;
					proxy_warning("Killing client connection %s:%d because inactive for %llums\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, sess_time / 1000);
				}
			}
#endif // IDLE_THREADS
		}
		else {
			// NOTE: we used the special value -1 to inform PgSQL_Session::handler() to recompute it
			// removing this logic in 2.0.15
			//sess->active_transactions = -1;
		}
		if (sess->healthy == 0) {
			char _buf[1024];
			if (sess->client_myds) {
				if (pgsql_thread___log_unhealthy_connections) {
					if (sess->session_fast_forward == false) {
						proxy_warning(
							"Closing unhealthy client connection %s:%d\n", sess->client_myds->addr.addr,
							sess->client_myds->addr.port
						);
					}
					else {
						proxy_warning(
							"Closing 'fast_forward' client connection %s:%d\n", sess->client_myds->addr.addr,
							sess->client_myds->addr.port
						);
					}
				}
			}
			sprintf(_buf, "%s:%d:%s()", __FILE__, __LINE__, __func__);
			GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, sess, NULL, _buf);
			unregister_session(n);
			n--;
			delete sess;
		}
		else {
			if (sess->to_process == 1) {
				if (sess->pause_until <= curtime) {
					rc = sess->handler();
					//total_active_transactions_+=sess->active_transactions;
					if (rc == -1 || sess->killed == true) {
						char _buf[1024];
						if (sess->client_myds && sess->killed)
							proxy_warning("Closing killed client connection %s:%d\n", sess->client_myds->addr.addr, sess->client_myds->addr.port);
						sprintf(_buf, "%s:%d:%s()", __FILE__, __LINE__, __func__);
						GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, sess, NULL, _buf);
						unregister_session(n);
						n--;
						delete sess;
					}
				}
			}
			else {
				if (sess->killed == true) {
					// this is a special cause, if killed the session needs to be executed no matter if paused
					sess->handler();
					char _buf[1024];
					if (sess->client_myds)
						proxy_warning("Closing killed client connection %s:%d\n", sess->client_myds->addr.addr, sess->client_myds->addr.port);
					sprintf(_buf, "%s:%d:%s()", __FILE__, __LINE__, __func__);
					GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, sess, NULL, _buf);
					unregister_session(n);
					n--;
					delete sess;
				}
			}
		}
	}
	if (maintenance_loop) {
		unsigned int total_active_transactions_tmp;
		total_active_transactions_tmp = __sync_add_and_fetch(&status_variables.active_transactions, 0);
		__sync_bool_compare_and_swap(&status_variables.active_transactions, total_active_transactions_tmp, total_active_transactions_);
	}
}

void PgSQL_Thread::refresh_variables() {
	pthread_mutex_lock(&GloVars.global.ext_glomth_mutex);
	if (GloPTH == NULL) {
		return;
	}
	GloPTH->wrlock();
	__thread_PgSQL_Thread_Variables_version = __global_PgSQL_Thread_Variables_version;
	pgsql_thread___authentication_method = GloPTH->get_variable_int((char*)"authentication_method");
	pgsql_thread___show_processlist_extended = GloPTH->get_variable_int((char*)"show_processlist_extended");
	pgsql_thread___max_connections = GloPTH->get_variable_int((char*)"max_connections");
	pgsql_thread___use_tcp_keepalive = (bool)GloPTH->get_variable_int((char*)"use_tcp_keepalive");
	pgsql_thread___tcp_keepalive_time = GloPTH->get_variable_int((char*)"tcp_keepalive_time");
	pgsql_thread___throttle_connections_per_sec_to_hostgroup = GloPTH->get_variable_int((char*)"throttle_connections_per_sec_to_hostgroup");
	pgsql_thread___max_transaction_idle_time = GloPTH->get_variable_int((char*)"max_transaction_idle_time");
	pgsql_thread___max_transaction_time = GloPTH->get_variable_int((char*)"max_transaction_time");
	pgsql_thread___threshold_query_length = GloPTH->get_variable_int((char*)"threshold_query_length");
	pgsql_thread___threshold_resultset_size = GloPTH->get_variable_int((char*)"threshold_resultset_size");
	pgsql_thread___poll_timeout = GloPTH->get_variable_int((char*)"poll_timeout");
	pgsql_thread___poll_timeout_on_failure = GloPTH->get_variable_int((char*)"poll_timeout_on_failure");
	pgsql_thread___wait_timeout = GloPTH->get_variable_int((char*)"wait_timeout");
	pgsql_thread___client_host_cache_size = GloPTH->get_variable_int((char*)"client_host_cache_size");
	pgsql_thread___client_host_error_counts = GloPTH->get_variable_int((char*)"client_host_error_counts");
	pgsql_thread___connect_retries_on_failure = GloPTH->get_variable_int((char*)"connect_retries_on_failure");
	pgsql_thread___connect_retries_delay = GloPTH->get_variable_int((char*)"connect_retries_delay");
	pgsql_thread___multiplexing = (bool)GloPTH->get_variable_int((char*)"multiplexing");
	pgsql_thread___connection_delay_multiplex_ms = GloPTH->get_variable_int((char*)"connection_delay_multiplex_ms");
	pgsql_thread___connection_max_age_ms = GloPTH->get_variable_int((char*)"connection_max_age_ms");
	pgsql_thread___connect_timeout_client = GloPTH->get_variable_int((char*)"connect_timeout_client");
	pgsql_thread___connect_timeout_server = GloPTH->get_variable_int((char*)"connect_timeout_server");
	pgsql_thread___connect_timeout_server_max = GloPTH->get_variable_int((char*)"connect_timeout_server_max");
	pgsql_thread___connection_warming = (bool)GloPTH->get_variable_int((char*)"connection_warming");
	pgsql_thread___log_unhealthy_connections = (bool)GloPTH->get_variable_int((char*)"log_unhealthy_connections");
	pgsql_thread___throttle_max_bytes_per_second_to_client = GloPTH->get_variable_int((char*)"throttle_max_bytes_per_second_to_client");
	pgsql_thread___throttle_ratio_server_to_client = GloPTH->get_variable_int((char*)"throttle_ratio_server_to_client");
	pgsql_thread___shun_on_failures = GloPTH->get_variable_int((char*)"shun_on_failures");
	pgsql_thread___shun_recovery_time_sec = GloPTH->get_variable_int((char*)"shun_recovery_time_sec");
	pgsql_thread___hostgroup_manager_verbose = GloPTH->get_variable_int((char*)"hostgroup_manager_verbose");
	pgsql_thread___default_max_latency_ms = GloPTH->get_variable_int((char*)"default_max_latency_ms");
	pgsql_thread___unshun_algorithm = GloPTH->get_variable_int((char*)"unshun_algorithm");
	pgsql_thread___free_connections_pct = GloPTH->get_variable_int((char*)"free_connections_pct");
	pgsql_thread___kill_backend_connection_when_disconnect = (bool)GloPTH->get_variable_int((char*)"kill_backend_connection_when_disconnect");
	pgsql_thread___max_allowed_packet = GloPTH->get_variable_int((char*)"max_allowed_packet");
	pgsql_thread___set_query_lock_on_hostgroup = GloPTH->get_variable_int((char*)"set_query_lock_on_hostgroup");
	pgsql_thread___verbose_query_error = (bool)GloPTH->get_variable_int((char*)"verbose_query_error");
#ifdef IDLE_THREADS
	pgsql_thread___session_idle_ms = GloPTH->get_variable_int((char*)"session_idle_ms");
#endif // IDLE_THREADS
	pgsql_thread___long_query_time = GloPTH->get_variable_int((char*)"long_query_time");
	pgsql_thread___set_parser_algorithm = GloPTH->get_variable_int((char*)"set_parser_algorithm");
	pgsql_thread___parse_failure_logs_digest = (bool)GloPTH->get_variable_int((char*)"parse_failure_logs_digest");
	pgsql_thread___auto_increment_delay_multiplex = GloPTH->get_variable_int((char*)"auto_increment_delay_multiplex");
	pgsql_thread___auto_increment_delay_multiplex_timeout_ms = GloPTH->get_variable_int((char*)"auto_increment_delay_multiplex_timeout_ms");
	pgsql_thread___default_query_delay = GloPTH->get_variable_int((char*)"default_query_delay");
	pgsql_thread___default_query_timeout = GloPTH->get_variable_int((char*)"default_query_timeout");
	pgsql_thread___query_retries_on_failure = GloPTH->get_variable_int((char*)"query_retries_on_failure");
	pgsql_thread___ping_interval_server_msec = GloPTH->get_variable_int((char*)"ping_interval_server_msec");
	pgsql_thread___ping_timeout_server = GloPTH->get_variable_int((char*)"ping_timeout_server");
	pgsql_thread___mirror_max_concurrency = GloPTH->get_variable_int((char*)"mirror_max_concurrency");
	pgsql_thread___mirror_max_queue_length = GloPTH->get_variable_int((char*)"mirror_max_queue_length");
	pgsql_thread___sessions_sort = (bool)GloPTH->get_variable_int((char*)"sessions_sort");
	pgsql_thread___show_processlist_extended = GloPTH->get_variable_int((char*)"show_processlist_extended");
	pgsql_thread___servers_stats = (bool)GloPTH->get_variable_int((char*)"servers_stats");
	pgsql_thread___default_reconnect = (bool)GloPTH->get_variable_int((char*)"default_reconnect");
	
	pgsql_thread___automatic_detect_sqli = (bool)GloPTH->get_variable_int((char*)"automatic_detect_sqli");
	
	pgsql_thread___firewall_whitelist_enabled = (bool)GloPTH->get_variable_int((char*)"firewall_whitelist_enabled");
	pgsql_thread___query_digests_max_digest_length = GloPTH->get_variable_int((char*)"query_digests_max_digest_length");
	pgsql_thread___query_digests_max_query_length = GloPTH->get_variable_int((char*)"query_digests_max_query_length");
	pgsql_thread___query_processor_iterations = GloPTH->get_variable_int((char*)"query_processor_iterations");
	pgsql_thread___query_processor_regex = GloPTH->get_variable_int((char*)"query_processor_regex");

	mysql_thread___query_cache_size_MB = GloPTH->get_variable_int((char*)"query_cache_size_MB");
	mysql_thread___query_cache_soft_ttl_pct = GloPTH->get_variable_int((char*)"query_cache_soft_ttl_pct");
	mysql_thread___query_cache_handle_warnings = GloPTH->get_variable_int((char*)"query_cache_handle_warnings");
	/*
	mysql_thread___max_stmts_per_connection = GloPTH->get_variable_int((char*)"max_stmts_per_connection");
	mysql_thread___max_stmts_cache = GloPTH->get_variable_int((char*)"max_stmts_cache");

	*/
	if (mysql_thread___monitor_username) free(mysql_thread___monitor_username);
	mysql_thread___monitor_username = GloPTH->get_variable_string((char*)"monitor_username");
	if (mysql_thread___monitor_password) free(mysql_thread___monitor_password);
	mysql_thread___monitor_password = GloPTH->get_variable_string((char*)"monitor_password");
	/*if (mysql_thread___monitor_replication_lag_use_percona_heartbeat) free(mysql_thread___monitor_replication_lag_use_percona_heartbeat);
	mysql_thread___monitor_replication_lag_use_percona_heartbeat = GloPTH->get_variable_string((char*)"monitor_replication_lag_use_percona_heartbeat");

	mysql_thread___monitor_wait_timeout = (bool)GloPTH->get_variable_int((char*)"monitor_wait_timeout");
	mysql_thread___monitor_writer_is_also_reader = (bool)GloPTH->get_variable_int((char*)"monitor_writer_is_also_reader");
	*/

	pgsql_thread___monitor_enabled = (bool)GloPTH->get_variable_int((char*)"monitor_enabled");
	pgsql_thread___monitor_history = GloPTH->get_variable_int((char*)"monitor_history");
	pgsql_thread___monitor_connect_interval = GloPTH->get_variable_int((char*)"monitor_connect_interval");
	pgsql_thread___monitor_connect_timeout = GloPTH->get_variable_int((char*)"monitor_connect_timeout");
	pgsql_thread___monitor_ping_interval = GloPTH->get_variable_int((char*)"monitor_ping_interval");
	pgsql_thread___monitor_ping_max_failures = GloPTH->get_variable_int((char*)"monitor_ping_max_failures");
	pgsql_thread___monitor_ping_timeout = GloPTH->get_variable_int((char*)"monitor_ping_timeout");
	pgsql_thread___monitor_read_only_interval = GloPTH->get_variable_int((char*)"monitor_read_only_interval");
	pgsql_thread___monitor_read_only_timeout = GloPTH->get_variable_int((char*)"monitor_read_only_timeout");
	pgsql_thread___monitor_threads = GloPTH->get_variable_int((char*)"monitor_threads");
	if (pgsql_thread___monitor_username) free(pgsql_thread___monitor_username);
	pgsql_thread___monitor_username = GloPTH->get_variable_string((char*)"monitor_username");
	if (pgsql_thread___monitor_password) free(pgsql_thread___monitor_password);
	pgsql_thread___monitor_password = GloPTH->get_variable_string((char*)"monitor_password");

	/*
    mysql_thread___monitor_aws_rds_topology_discovery_interval = GloPTH->get_variable_int((char *)"monitor_aws_rds_topology_discovery_interval");
	mysql_thread___monitor_read_only_max_timeout_count = GloPTH->get_variable_int((char*)"monitor_read_only_max_timeout_count");
	mysql_thread___monitor_replication_lag_group_by_host = (bool)GloPTH->get_variable_int((char*)"monitor_replication_lag_group_by_host");
	mysql_thread___monitor_replication_lag_interval = GloPTH->get_variable_int((char*)"monitor_replication_lag_interval");
	mysql_thread___monitor_replication_lag_timeout = GloPTH->get_variable_int((char*)"monitor_replication_lag_timeout");
	mysql_thread___monitor_replication_lag_count = GloPTH->get_variable_int((char*)"monitor_replication_lag_count");
	mysql_thread___monitor_groupreplication_healthcheck_interval = GloPTH->get_variable_int((char*)"monitor_groupreplication_healthcheck_interval");
	mysql_thread___monitor_groupreplication_healthcheck_timeout = GloPTH->get_variable_int((char*)"monitor_groupreplication_healthcheck_timeout");
	mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count = GloPTH->get_variable_int((char*)"monitor_groupreplication_healthcheck_max_timeout_count");
	mysql_thread___monitor_groupreplication_max_transactions_behind_count = GloPTH->get_variable_int((char*)"monitor_groupreplication_max_transactions_behind_count");
	mysql_thread___monitor_groupreplication_max_transaction_behind_for_read_only = GloPTH->get_variable_int((char*)"monitor_groupreplication_max_transactions_behind_for_read_only");
	mysql_thread___monitor_galera_healthcheck_interval = GloPTH->get_variable_int((char*)"monitor_galera_healthcheck_interval");
	mysql_thread___monitor_galera_healthcheck_timeout = GloPTH->get_variable_int((char*)"monitor_galera_healthcheck_timeout");
	mysql_thread___monitor_galera_healthcheck_max_timeout_count = GloPTH->get_variable_int((char*)"monitor_galera_healthcheck_max_timeout_count");
	mysql_thread___monitor_query_interval = GloPTH->get_variable_int((char*)"monitor_query_interval");
	mysql_thread___monitor_query_timeout = GloPTH->get_variable_int((char*)"monitor_query_timeout");
	mysql_thread___monitor_slave_lag_when_null = GloPTH->get_variable_int((char*)"monitor_slave_lag_when_null");
	mysql_thread___monitor_threads_min = GloPTH->get_variable_int((char*)"monitor_threads_min");
	mysql_thread___monitor_threads_max = GloPTH->get_variable_int((char*)"monitor_threads_max");
	mysql_thread___monitor_threads_queue_maxsize = GloPTH->get_variable_int((char*)"monitor_threads_queue_maxsize");
	mysql_thread___monitor_local_dns_cache_ttl = GloPTH->get_variable_int((char*)"monitor_local_dns_cache_ttl");
	mysql_thread___monitor_local_dns_cache_refresh_interval = GloPTH->get_variable_int((char*)"monitor_local_dns_cache_refresh_interval");
	mysql_thread___monitor_local_dns_resolver_queue_maxsize = GloPTH->get_variable_int((char*)"monitor_local_dns_resolver_queue_maxsize");
	*/
	if (pgsql_thread___firewall_whitelist_errormsg) free(pgsql_thread___firewall_whitelist_errormsg);
	pgsql_thread___firewall_whitelist_errormsg = GloPTH->get_variable_string((char*)"firewall_whitelist_errormsg");
	/*
	if (mysql_thread___ldap_user_variable) free(mysql_thread___ldap_user_variable);
	mysql_thread___ldap_user_variable = GloPTH->get_variable_string((char*)"ldap_user_variable");
	if (mysql_thread___add_ldap_user_comment) free(mysql_thread___add_ldap_user_comment);
	mysql_thread___add_ldap_user_comment = GloPTH->get_variable_string((char*)"add_ldap_user_comment");
	if (mysql_thread___default_session_track_gtids) free(mysql_thread___default_session_track_gtids);
	mysql_thread___default_session_track_gtids = GloPTH->get_variable_string((char*)"default_session_track_gtids");

	for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		if (mysql_thread___default_variables[i]) {
			free(mysql_thread___default_variables[i]);
			mysql_thread___default_variables[i] = NULL;
		}
		char buf[128];
		if (mysql_tracked_variables[i].is_global_variable) {
			sprintf(buf, "default_%s", mysql_tracked_variables[i].internal_variable_name);
			mysql_thread___default_variables[i] = GloPTH->get_variable_string(buf);
		}
	}
*/
	if (pgsql_thread___init_connect) free(pgsql_thread___init_connect);
	pgsql_thread___init_connect = GloPTH->get_variable_string((char*)"init_connect");

	// SSL proxy to server
	if (pgsql_thread___ssl_p2s_ca) free(pgsql_thread___ssl_p2s_ca);
	pgsql_thread___ssl_p2s_ca = GloPTH->get_variable_string((char*)"ssl_p2s_ca");
	if (pgsql_thread___ssl_p2s_capath) free(pgsql_thread___ssl_p2s_capath);
	pgsql_thread___ssl_p2s_capath = GloPTH->get_variable_string((char*)"ssl_p2s_capath");
	if (pgsql_thread___ssl_p2s_cert) free(pgsql_thread___ssl_p2s_cert);
	pgsql_thread___ssl_p2s_cert = GloPTH->get_variable_string((char*)"ssl_p2s_cert");
	if (pgsql_thread___ssl_p2s_key) free(pgsql_thread___ssl_p2s_key);
	pgsql_thread___ssl_p2s_key = GloPTH->get_variable_string((char*)"ssl_p2s_key");
	if (pgsql_thread___ssl_p2s_cipher) free(pgsql_thread___ssl_p2s_cipher);
	pgsql_thread___ssl_p2s_cipher = GloPTH->get_variable_string((char*)"ssl_p2s_cipher");
	if (pgsql_thread___ssl_p2s_crl) free(pgsql_thread___ssl_p2s_crl);
	pgsql_thread___ssl_p2s_crl = GloPTH->get_variable_string((char*)"ssl_p2s_crl");
	if (pgsql_thread___ssl_p2s_crlpath) free(pgsql_thread___ssl_p2s_crlpath);
	pgsql_thread___ssl_p2s_crlpath = GloPTH->get_variable_string((char*)"ssl_p2s_crlpath");

	if (pgsql_thread___server_version) free(pgsql_thread___server_version);
	pgsql_thread___server_version = GloPTH->get_variable_string((char*)"server_version");
	if (pgsql_thread___default_client_encoding) free(pgsql_thread___default_client_encoding);
	pgsql_thread___default_client_encoding = GloPTH->get_variable_string((char*)"default_client_encoding");

	pgsql_thread___have_ssl = (bool)GloPTH->get_variable_int((char*)"have_ssl");

	if (pgsql_thread___eventslog_filename) free(pgsql_thread___eventslog_filename);
	pgsql_thread___eventslog_filesize = GloPTH->get_variable_int((char*)"eventslog_filesize");
	pgsql_thread___eventslog_default_log = GloPTH->get_variable_int((char*)"eventslog_default_log");
	pgsql_thread___eventslog_format = GloPTH->get_variable_int((char*)"eventslog_format");
	pgsql_thread___eventslog_filename = GloPTH->get_variable_string((char*)"eventslog_filename");
	if (pgsql_thread___auditlog_filename) free(pgsql_thread___auditlog_filename);
	pgsql_thread___auditlog_filesize = GloPTH->get_variable_int((char*)"auditlog_filesize");
	pgsql_thread___auditlog_filename = GloPTH->get_variable_string((char*)"auditlog_filename");

	GloPgSQL_Logger->events_set_base_filename(); // both filename and filesize are set here
	GloPgSQL_Logger->audit_set_base_filename(); // both filename and filesize are set here

	//if (pgsql_thread___default_schema) free(pgsql_thread___default_schema);
	//pgsql_thread___default_schema = GloPTH->get_variable_string((char*)"default_schema");
	if (pgsql_thread___keep_multiplexing_variables) free(pgsql_thread___keep_multiplexing_variables);
	pgsql_thread___keep_multiplexing_variables = GloPTH->get_variable_string((char*)"keep_multiplexing_variables");

	/*
	mysql_thread___server_capabilities = GloPTH->get_variable_uint16((char*)"server_capabilities");
	mysql_thread___handle_unknown_charset = GloPTH->get_variable_int((char*)"handle_unknown_charset");
	mysql_thread___have_compress = (bool)GloPTH->get_variable_int((char*)"have_compress");
	
	mysql_thread___enforce_autocommit_on_reads = (bool)GloPTH->get_variable_int((char*)"enforce_autocommit_on_reads");
	mysql_thread___autocommit_false_not_reusable = (bool)GloPTH->get_variable_int((char*)"autocommit_false_not_reusable");
	mysql_thread___autocommit_false_is_transaction = (bool)GloPTH->get_variable_int((char*)"autocommit_false_is_transaction");
	*/
	pgsql_thread___commands_stats = (bool)GloPTH->get_variable_int((char*)"commands_stats");
	pgsql_thread___query_digests = (bool)GloPTH->get_variable_int((char*)"query_digests");
	pgsql_thread___query_digests_lowercase = (bool)GloPTH->get_variable_int((char*)"query_digests_lowercase");
	pgsql_thread___query_digests_replace_null = (bool)GloPTH->get_variable_int((char*)"query_digests_replace_null");
	pgsql_thread___query_digests_no_digits = (bool)GloPTH->get_variable_int((char*)"query_digests_no_digits");
	pgsql_thread___query_digests_normalize_digest_text = (bool)GloPTH->get_variable_int((char*)"query_digests_normalize_digest_text");
	pgsql_thread___query_digests_track_hostname = (bool)GloPTH->get_variable_int((char*)"query_digests_track_hostname");
	pgsql_thread___query_digests_grouping_limit = (int)GloPTH->get_variable_int((char*)"query_digests_grouping_limit");
	pgsql_thread___query_digests_groups_grouping_limit = (int)GloPTH->get_variable_int((char*)"query_digests_groups_grouping_limit");
	pgsql_thread___query_digests_keep_comment = (bool)GloPTH->get_variable_int((char*)"query_digests_keep_comment");
	/*
	variables.min_num_servers_lantency_awareness = GloPTH->get_variable_int((char*)"min_num_servers_lantency_awareness");
	variables.aurora_max_lag_ms_only_read_from_replicas = GloPTH->get_variable_int((char*)"aurora_max_lag_ms_only_read_from_replicas");
	variables.stats_time_backend_query = (bool)GloPTH->get_variable_int((char*)"stats_time_backend_query");
	variables.stats_time_query_processor = (bool)GloPTH->get_variable_int((char*)"stats_time_query_processor");
	variables.query_cache_stores_empty_result = (bool)GloPTH->get_variable_int((char*)"query_cache_stores_empty_result");
	
	mysql_thread___client_session_track_gtid = (bool)GloPTH->get_variable_int((char*)"client_session_track_gtid");

#ifdef IDLE_THREADS
	mysql_thread___session_idle_show_processlist = (bool)GloPTH->get_variable_int((char*)"session_idle_show_processlist");
#endif // IDLE_THREADS
	
	mysql_thread___enable_client_deprecate_eof = (bool)GloPTH->get_variable_int((char*)"enable_client_deprecate_eof");
	mysql_thread___enable_server_deprecate_eof = (bool)GloPTH->get_variable_int((char*)"enable_server_deprecate_eof");
	*/
	pgsql_thread___enable_load_data_local_infile = (bool)GloPTH->get_variable_int((char*)"enable_load_data_local_infile");
	/*mysql_thread___log_mysql_warnings_enabled = (bool)GloPTH->get_variable_int((char*)"log_mysql_warnings_enabled");
	mysql_thread___client_host_cache_size = GloPTH->get_variable_int((char*)"client_host_cache_size");
	mysql_thread___client_host_error_counts = GloPTH->get_variable_int((char*)"client_host_error_counts");
	mysql_thread___handle_warnings = GloPTH->get_variable_int((char*)"handle_warnings");
#ifdef DEBUG
	mysql_thread___session_debug = (bool)GloPTH->get_variable_int((char*)"session_debug");
#endif // DEBUG
*/
	GloPTH->wrunlock();
	pthread_mutex_unlock(&GloVars.global.ext_glomth_mutex);
}

PgSQL_Thread::PgSQL_Thread() {
	pthread_mutex_init(&thread_mutex, NULL);
	my_idle_conns = NULL;
	cached_connections = NULL;
	mysql_sessions = NULL;
	mirror_queue_mysql_sessions = NULL;
	mirror_queue_mysql_sessions_cache = NULL;
#ifdef IDLE_THREADS
	efd = -1;
	epoll_thread = false;
	mysess_idx = 0;
	idle_mysql_sessions = NULL;
	resume_mysql_sessions = NULL;
	myexchange.idle_mysql_sessions = NULL;
	myexchange.resume_mysql_sessions = NULL;
#endif // IDLE_THREADS
	processing_idles = false;
	last_processing_idles = 0;
	__thread_PgSQL_Thread_Variables_version = 0;
	pgsql_thread___server_version = NULL;
	pgsql_thread___default_client_encoding = NULL;
	pgsql_thread___have_ssl = true;
	//pgsql_thread___default_schema = NULL;
	pgsql_thread___init_connect = NULL;
	//pgsql_thread___ldap_user_variable = NULL;
	//pgsql_thread___add_ldap_user_comment = NULL;
	pgsql_thread___eventslog_filename = NULL;
	pgsql_thread___auditlog_filename = NULL;

	// SSL proxy to server
	pgsql_thread___ssl_p2s_ca = NULL;
	pgsql_thread___ssl_p2s_capath = NULL;
	pgsql_thread___ssl_p2s_cert = NULL;
	pgsql_thread___ssl_p2s_key = NULL;
	pgsql_thread___ssl_p2s_cipher = NULL;
	pgsql_thread___ssl_p2s_crl = NULL;
	pgsql_thread___ssl_p2s_crlpath = NULL;

	last_maintenance_time = 0;
	last_move_to_idle_thread_time = 0;
	maintenance_loop = true;

	servers_table_version_previous = 0;
	servers_table_version_current = 0;

	status_variables.active_transactions = 0;

	for (unsigned int i = 0; i < PG_st_var_END; i++) {
		status_variables.stvar[i] = 0;
	}
	match_regexes = NULL;

	variables.min_num_servers_lantency_awareness = 1000;
	variables.aurora_max_lag_ms_only_read_from_replicas = 2;
	variables.stats_time_backend_query = false;
	variables.stats_time_query_processor = false;
	variables.query_cache_stores_empty_result = true;

	for (int i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		mysql_thread___default_variables[i] = NULL;
	}
	shutdown = 0;
	thr_SetParser = NULL;
}

void PgSQL_Thread::register_session_connection_handler(PgSQL_Session * _sess, bool _new) {
	_sess->thread = this;
	_sess->connections_handler = true;
	assert(_new);
	mysql_sessions->add(_sess);
}

void PgSQL_Thread::unregister_session_connection_handler(int idx, bool _new) {
	assert(_new);
	mysql_sessions->remove_index_fast(idx);
}

void PgSQL_Thread::listener_handle_new_connection(PgSQL_Data_Stream * myds, unsigned int n) {
	int c;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} custom_sockaddr;
	struct sockaddr* addr = (struct sockaddr*)malloc(sizeof(custom_sockaddr));
	socklen_t addrlen = sizeof(custom_sockaddr);
	memset(addr, 0, sizeof(custom_sockaddr));
	if (GloPTH->num_threads > 1) {
		// there are more than 1 thread . We pause for a little bit to avoid all connections to be handled by the same thread
#ifdef SO_REUSEPORT
		if (GloVars.global.reuseport == false) { // only if reuseport is not enabled
			//usleep(10+rand()%50);
		}
#else
		//usleep(10+rand()%50);
#endif /* SO_REUSEPORT */
	}
	c = accept(myds->fd, addr, &addrlen);
	if (c > -1) { // accept() succeeded
		if (pgsql_thread___client_host_cache_size) {
			PgSQL_Client_Host_Cache_Entry client_host_entry =
				GloPTH->find_client_host_cache(addr);
			if (
				client_host_entry.updated_at != 0 &&
				client_host_entry.error_count >= static_cast<uint32_t>(pgsql_thread___client_host_error_counts)
				) {
				std::string client_addr = get_client_addr(addr);
				proxy_error(
					"Closing connection because client '%s' reached 'pgsql-client_host_error_counts': %d\n",
					client_addr.c_str(), pgsql_thread___client_host_error_counts
				);
				close(c);
				free(addr);
				status_variables.stvar[st_var_client_host_error_killed_connections] += 1;
				return;
			}
		}

		// create a new client connection
		mypolls.fds[n].revents = 0;
		PgSQL_Session* sess = create_new_session_and_client_data_stream<PgSQL_Thread,PgSQL_Session*>(c);
		__sync_add_and_fetch(&PgHGM->status.client_connections_created, 1);
		if (__sync_add_and_fetch(&PgHGM->status.client_connections, 1) > pgsql_thread___max_connections) {
			sess->max_connections_reached = true;
		}
		sess->client_myds->client_addrlen = addrlen;
		sess->client_myds->client_addr = addr;

		switch (sess->client_myds->client_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)sess->client_myds->client_addr;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
			sess->client_myds->addr.addr = strdup(buf);
			sess->client_myds->addr.port = htons(ipv4->sin_port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sess->client_myds->client_addr;
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
			sess->client_myds->addr.addr = strdup(buf);
			sess->client_myds->addr.port = htons(ipv6->sin6_port);
			break;
		}
		default:
			sess->client_myds->addr.addr = strdup("localhost");
			break;
		}

		iface_info* ifi = NULL;
		ifi = GloPTH->MLM_find_iface_from_fd(myds->fd); // here we try to get the info about the proxy bind address
		if (ifi) {
			sess->client_myds->proxy_addr.addr = strdup(ifi->address);
			sess->client_myds->proxy_addr.port = ifi->port;
		}
		//sess->client_myds->myprot.generate_pkt_initial_handshake(true, NULL, NULL, &sess->thread_session_id, true);

		sess->client_myds->DSS = STATE_SERVER_HANDSHAKE;
		sess->status = CONNECTING_CLIENT;

		ioctl_FIONBIO(sess->client_myds->fd, 1);
		mypolls.add(POLLIN | POLLOUT, sess->client_myds->fd, sess->client_myds, curtime);
		proxy_debug(PROXY_DEBUG_NET, 1, "Session=%p -- Adding client FD %d\n", sess, sess->client_myds->fd);

		// we now enforce sending the 'initial handshake packet' as soon as it's generated. This
		// is done to prevent situations in which a client sends a packet *before* receiving
		// this 'initial handshake', leading to invalid state in dataflow, since it will be
		// data in both ends of the datastream. For more details see #3342.
		//sess->writeout();
	}
	else {
		free(addr);
		// if we arrive here, accept() failed
		// because multiple threads try to handle the same incoming connection, this is OK
	}
}

SQLite3_result* PgSQL_Threads_Handler::SQL3_GlobalStatus(bool _memory) {
	const int colnum = 2;
	char buf[256];
	char** pta = (char**)malloc(sizeof(char*) * colnum);
	if (_memory == true) {
		Get_Memory_Stats();
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping PgSQL Global Status\n");
	SQLite3_result* result = new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT, "Variable_Name");
	result->add_column_definition(SQLITE_TEXT, "Variable_Value");
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
	{ // uptime
		unsigned long long t1 = monotonic_time();
		pta[0] = (char*)"ProxySQL_Uptime";
		sprintf(buf, "%llu", (t1 - GloVars.global.start_time) / 1000 / 1000);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Active Transactions
		pta[0] = (char*)"Active_Transactions";
		sprintf(buf, "%u", get_active_transations());
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Connections created
		pta[0] = (char*)"Client_Connections_aborted";
		sprintf(buf, "%lu", PgHGM->status.client_connections_aborted);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Connections
		pta[0] = (char*)"Client_Connections_connected";
		sprintf(buf, "%d", PgHGM->status.client_connections);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Connections created
		pta[0] = (char*)"Client_Connections_created";
		sprintf(buf, "%lu", PgHGM->status.client_connections_created);
		pta[1] = buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0] = (char*)"Server_Connections_aborted";
		sprintf(buf, "%lu", PgHGM->status.server_connections_aborted);
		pta[1] = buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0] = (char*)"Server_Connections_connected";
		sprintf(buf, "%lu", PgHGM->status.server_connections_connected);
		pta[1] = buf;
		result->add_row(pta);
	}
	{
		// Connections
		pta[0] = (char*)"Server_Connections_created";
		sprintf(buf, "%lu", PgHGM->status.server_connections_created);
		pta[1] = buf;
		result->add_row(pta);
	}
	{
		// Connections delayed
		pta[0] = (char*)"Server_Connections_delayed";
		sprintf(buf, "%lu", PgHGM->status.server_connections_delayed);
		pta[1] = buf;
		result->add_row(pta);
	}
#ifdef IDLE_THREADS
	{	// Connections non idle
		pta[0] = (char*)"Client_Connections_non_idle";
		sprintf(buf, "%u", get_non_idle_client_connections());
		pta[1] = buf;
		result->add_row(pta);
	}
#endif // IDLE_THREADS
	{	// PgSQL Backend buffers bytes
		pta[0] = (char*)"pgsql_backend_buffers_bytes";
		sprintf(buf, "%llu", get_pgsql_backend_buffers_bytes());
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// PgSQL Frontend buffers bytes
		pta[0] = (char*)"pgsql_frontend_buffers_bytes";
		sprintf(buf, "%llu", get_pgsql_frontend_buffers_bytes());
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// PgSQL Frontend buffers bytes
		pta[0] = (char*)"pgsql_session_internal_bytes";
		sprintf(buf, "%llu", get_pgsql_session_internal_bytes());
		pta[1] = buf;
		result->add_row(pta);
	}
	/*{	// Queries autocommit
		pta[0] = (char*)"Com_autocommit";
		sprintf(buf, "%llu", PgHGM->status.autocommit_cnt);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries filtered autocommit
		pta[0] = (char*)"Com_autocommit_filtered";
		sprintf(buf, "%llu", PgHGM->status.autocommit_cnt_filtered);
		pta[1] = buf;
		result->add_row(pta);
	}*/
	{	// Queries commit
		pta[0] = (char*)"Commit";
		sprintf(buf, "%llu", PgHGM->status.commit_cnt);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries filtered commit
		pta[0] = (char*)"Commit_filtered";
		sprintf(buf, "%llu", PgHGM->status.commit_cnt_filtered);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries rollback
		pta[0] = (char*)"Rollback";
		sprintf(buf, "%llu", PgHGM->status.rollback_cnt);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries filtered rollback
		pta[0] = (char*)"Rollback_filtered";
		sprintf(buf, "%llu", PgHGM->status.rollback_cnt_filtered);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries backend RESET_CONNECTION
		pta[0] = (char*)"Backend_reset_connection";
		sprintf(buf, "%llu", PgHGM->status.backend_reset_connection);
		pta[1] = buf;
		result->add_row(pta);
	}
	/* {	// Queries backend INIT DB
		pta[0] = (char*)"Com_backend_init_db";
		sprintf(buf, "%llu", PgHGM->status.backend_init_db);
		pta[1] = buf;
		result->add_row(pta);
	}*/
	{	// Queries backend SET client_encoding 
		pta[0] = (char*)"Backend_set_client_encoding";
		sprintf(buf, "%llu", PgHGM->status.backend_set_client_encoding);
		pta[1] = buf;
		result->add_row(pta);
	}
	/* {	// Queries frontend INIT DB
		pta[0] = (char*)"Com_frontend_init_db";
		sprintf(buf, "%llu", PgHGM->status.frontend_init_db);
		pta[1] = buf;
		result->add_row(pta);
	}*/
	{	// Queries frontend SET client_encoding 
		pta[0] = (char*)"Frontend_set_client_encoding";
		sprintf(buf, "%llu", PgHGM->status.frontend_set_client_encoding);
		pta[1] = buf;
		result->add_row(pta);
	}
	/* {	// Queries frontend USE DB
		pta[0] = (char*)"Com_frontend_use_db";
		sprintf(buf, "%llu", PgHGM->status.frontend_use_db);
		pta[1] = buf;
		result->add_row(pta);
	}*/
/*
	for (unsigned int i = 0; i < sizeof(PgSQL_Thread_status_variables_counter_array) / sizeof(mythr_st_vars_t); i++) {
		if (PgSQL_Thread_status_variables_counter_array[i].name) {
			if (strlen(PgSQL_Thread_status_variables_counter_array[i].name)) {
				pta[0] = PgSQL_Thread_status_variables_counter_array[i].name;
				unsigned long long stvar =
					get_status_variable(
						PgSQL_Thread_status_variables_counter_array[i].v_idx,
						PgSQL_Thread_status_variables_counter_array[i].m_idx,
						PgSQL_Thread_status_variables_counter_array[i].conv
					);
				sprintf(buf, "%llu", stvar);
				pta[1] = buf;
				result->add_row(pta);
			}
		}
	}
	// Gauge variables
	for (unsigned int i = 0; i < sizeof(PgSQL_Thread_status_variables_gauge_array) / sizeof(mythr_g_st_vars_t); i++) {
		if (PgSQL_Thread_status_variables_gauge_array[i].name) {
			if (strlen(PgSQL_Thread_status_variables_gauge_array[i].name)) {
				pta[0] = PgSQL_Thread_status_variables_gauge_array[i].name;
				unsigned long long stvar =
					get_status_variable(
						PgSQL_Thread_status_variables_gauge_array[i].v_idx,
						PgSQL_Thread_status_variables_gauge_array[i].m_idx,
						PgSQL_Thread_status_variables_gauge_array[i].conv
					);
				sprintf(buf, "%llu", stvar);
				pta[1] = buf;
				result->add_row(pta);
			}
		}
	}
*/
	{	// Mirror current concurrency
		pta[0] = (char*)"Mirror_concurrency";
		sprintf(buf, "%u", status_variables.mirror_sessions_current);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Mirror queue length
		pta[0] = (char*)"Mirror_queue_length";
		sprintf(buf, "%llu", get_total_mirror_queue());
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Queries that are SELECT for update or equivalent
		pta[0] = (char*)"Selects_for_update__autocommit0";
		sprintf(buf, "%llu", PgHGM->status.select_for_update_or_equivalent);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Servers_table_version
		pta[0] = (char*)"Servers_table_version";
		sprintf(buf, "%u", PgHGM->get_servers_table_version());
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// MySQL Threads workers
		pta[0] = (char*)"PgSQL_Thread_Workers";
		sprintf(buf, "%d", num_threads);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Access_Denied_Wrong_Password
		pta[0] = (char*)"Access_Denied_Wrong_Password";
		sprintf(buf, "%llu", PgHGM->status.access_denied_wrong_password);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Access_Denied_Max_Connections
		pta[0] = (char*)"Access_Denied_Max_Connections";
		sprintf(buf, "%llu", PgHGM->status.access_denied_max_connections);
		pta[1] = buf;
		result->add_row(pta);
	}
	{	// Access_Denied_Max_User_Connections
		pta[0] = (char*)"Access_Denied_Max_User_Connections";
		sprintf(buf, "%llu", PgHGM->status.access_denied_max_user_connections);
		pta[1] = buf;
		result->add_row(pta);
	}
	/*if (GloMyMon) {
		{	// MySQL Monitor workers
			pta[0] = (char*)"MySQL_Monitor_Workers";
			sprintf(buf, "%d", (variables.monitor_enabled ? GloMyMon->num_threads : 0));
			pta[1] = buf;
			result->add_row(pta);
		}
		{	// MySQL Monitor workers
			pta[0] = (char*)"MySQL_Monitor_Workers_Aux";
			sprintf(buf, "%d", (variables.monitor_enabled ? GloMyMon->aux_threads : 0));
			pta[1] = buf;
			result->add_row(pta);
		}
		{	// MySQL Monitor workers
			pta[0] = (char*)"MySQL_Monitor_Workers_Started";
			sprintf(buf, "%d", (variables.monitor_enabled ? GloMyMon->started_threads : 0));
			pta[1] = buf;
			result->add_row(pta);
		}
	*/
		{
			pta[0] = (char*)"PgSQL_Monitor_connect_check_OK";
			sprintf(buf, "%lu", GloPgMon->connect_check_OK);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"PgSQL_Monitor_connect_check_ERR";
			sprintf(buf, "%lu", GloPgMon->connect_check_ERR);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"PgSQL_Monitor_ping_check_OK";
			sprintf(buf, "%lu", GloPgMon->ping_check_OK);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"PgSQL_Monitor_ping_check_ERR";
			sprintf(buf, "%lu", GloPgMon->ping_check_ERR);
			pta[1] = buf;
			result->add_row(pta);
		}
		/*
		{
			pta[0] = (char*)"MySQL_Monitor_read_only_check_OK";
			sprintf(buf, "%llu", GloMyMon->read_only_check_OK);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_read_only_check_ERR";
			sprintf(buf, "%llu", GloMyMon->read_only_check_ERR);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_replication_lag_check_OK";
			sprintf(buf, "%llu", GloMyMon->replication_lag_check_OK);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_replication_lag_check_ERR";
			sprintf(buf, "%llu", GloMyMon->replication_lag_check_ERR);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_dns_cache_queried";
			sprintf(buf, "%llu", GloMyMon->dns_cache_queried);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_dns_cache_lookup_success";
			sprintf(buf, "%llu", GloMyMon->dns_cache_lookup_success);
			pta[1] = buf;
			result->add_row(pta);
		}
		{
			pta[0] = (char*)"MySQL_Monitor_dns_cache_record_updated";
			sprintf(buf, "%llu", GloMyMon->dns_cache_record_updated);
			pta[1] = buf;
			result->add_row(pta);
		}
	}*/
	free(pta);
	return result;
}


void PgSQL_Threads_Handler::Get_Memory_Stats() {
	unsigned int i;
	unsigned int j;
	j = num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		j += num_threads;
	}
#endif // IDLE_THREADS
	for (i = 0; i < j; i++) {
		PgSQL_Thread* thr = NULL;
		if (i < num_threads && pgsql_threads) {
			thr = (PgSQL_Thread*)pgsql_threads[i].worker;
#ifdef IDLE_THREADS
		}
		else {
			if (GloVars.global.idle_threads && pgsql_threads_idles) {
				thr = (PgSQL_Thread*)pgsql_threads_idles[i - num_threads].worker;
			}
#endif // IDLE_THREADS
		}
		if (thr == NULL) return; // quick exit, at least one thread is not ready
		pthread_mutex_lock(&thr->thread_mutex);
		thr->Get_Memory_Stats();
		pthread_mutex_unlock(&thr->thread_mutex);
	}
}

SQLite3_result* PgSQL_Threads_Handler::SQL3_Processlist() {
	const int colnum = 16;
	char port[NI_MAXSERV];
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping PgSQL Processlist\n");
	SQLite3_result* result = new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT, "ThreadID");
	result->add_column_definition(SQLITE_TEXT, "SessionID");
	result->add_column_definition(SQLITE_TEXT, "user");
	result->add_column_definition(SQLITE_TEXT, "database");
	result->add_column_definition(SQLITE_TEXT, "cli_host");
	result->add_column_definition(SQLITE_TEXT, "cli_port");
	result->add_column_definition(SQLITE_TEXT, "hostgroup");
	result->add_column_definition(SQLITE_TEXT, "l_srv_host");
	result->add_column_definition(SQLITE_TEXT, "l_srv_port");
	result->add_column_definition(SQLITE_TEXT, "srv_host");
	result->add_column_definition(SQLITE_TEXT, "srv_port");
	result->add_column_definition(SQLITE_TEXT, "command");
	result->add_column_definition(SQLITE_TEXT, "time_ms");
	result->add_column_definition(SQLITE_TEXT, "info");
	result->add_column_definition(SQLITE_TEXT, "status_flags");
	result->add_column_definition(SQLITE_TEXT, "extended_info");
	unsigned int i;
	unsigned int i2;
	//	signal_all_threads(1);
	i2 = num_threads;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		i2 += num_threads;
	}
#endif // IDLE_THREADS

	for (i = 0; i < i2; i++) {
		PgSQL_Thread* thr = NULL;
		if (i < num_threads && pgsql_threads) {
			thr = (PgSQL_Thread*)pgsql_threads[i].worker;
#ifdef IDLE_THREADS
		}
		else {
			if (GloVars.global.idle_threads && mysql_thread___session_idle_show_processlist && pgsql_threads_idles) {
				thr = (PgSQL_Thread*)pgsql_threads_idles[i - num_threads].worker;
			}
#endif // IDLE_THREADS
		}
		if (thr == NULL) break; // quick exit, at least one thread is not ready
		pthread_mutex_lock(&thr->thread_mutex);
		unsigned int j;
		for (j = 0; j < thr->mysql_sessions->len; j++) {
			PgSQL_Session* sess = (PgSQL_Session*)thr->mysql_sessions->pdata[j];
			if (sess->client_myds) {
				char buf[1024];
				char** pta = (char**)malloc(sizeof(char*) * colnum);
				sprintf(buf, "%d", i);
				pta[0] = strdup(buf);
				sprintf(buf, "%u", sess->thread_session_id);
				pta[1] = strdup(buf);
				PgSQL_Connection_userinfo* ui = sess->client_myds->myconn->userinfo;
				pta[2] = NULL;
				pta[3] = NULL;
				if (ui) {
					if (ui->username) {
						pta[2] = strdup(ui->username);
					}
					else {
						pta[2] = strdup("unauthenticated user");
					}
					if (ui->dbname) {
						pta[3] = strdup(ui->dbname);
					}
				}

				if (sess->mirror == false) {
					switch (sess->client_myds->client_addr->sa_family) {
					case AF_INET: {
						struct sockaddr_in* ipv4 = (struct sockaddr_in*)sess->client_myds->client_addr;
						inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
						pta[4] = strdup(buf);
						sprintf(port, "%d", ntohs(ipv4->sin_port));
						pta[5] = strdup(port);
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sess->client_myds->client_addr;
						inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
						pta[4] = strdup(buf);
						sprintf(port, "%d", ntohs(ipv6->sin6_port));
						pta[5] = strdup(port);
						break;
					}
					default:
						pta[4] = strdup("localhost");
						pta[5] = NULL;
						break;
					}
				}
				else {
					pta[4] = strdup("mirror_internal");
					pta[5] = NULL;
				}
				sprintf(buf, "%d", sess->current_hostgroup);
				pta[6] = strdup(buf);
				if (sess->mybe && sess->mybe->server_myds && sess->mybe->server_myds->myconn) {
					PgSQL_Connection* mc = sess->mybe->server_myds->myconn;


					struct sockaddr addr;
					socklen_t addr_len = sizeof(struct sockaddr);
					memset(&addr, 0, addr_len);
					int rc;
					rc = getsockname(mc->fd, &addr, &addr_len);
					if (rc == 0) {
						switch (addr.sa_family) {
						case AF_INET: {
							struct sockaddr_in* ipv4 = (struct sockaddr_in*)&addr;
							inet_ntop(addr.sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
							pta[7] = strdup(buf);
							sprintf(port, "%d", ntohs(ipv4->sin_port));
							pta[8] = strdup(port);
							break;
						}
						case AF_INET6: {
							struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&addr;
							inet_ntop(addr.sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
							pta[7] = strdup(buf);
							sprintf(port, "%d", ntohs(ipv6->sin6_port));
							pta[8] = strdup(port);
							break;
						}
						default:
							pta[7] = strdup("localhost");
							pta[8] = NULL;
							break;
						}
					}
					else {
						pta[7] = NULL;
						pta[8] = NULL;
					}

					sprintf(buf, "%s", mc->parent->address);
					pta[9] = strdup(buf);
					sprintf(buf, "%d", mc->parent->port);
					pta[10] = strdup(buf);
					if (sess->CurrentQuery.stmt_info == NULL) { // text protocol
						if (mc->query.length) {
							pta[13] = (char*)malloc(mc->query.length + 1);
							strncpy(pta[13], mc->query.ptr, mc->query.length);
							pta[13][mc->query.length] = '\0';
						}
						else {
							pta[13] = NULL;
						}
					}
					else { // prepared statement
						MySQL_STMT_Global_info* si = sess->CurrentQuery.stmt_info;
						if (si->query_length) {
							pta[13] = (char*)malloc(si->query_length + 1);
							strncpy(pta[13], si->query, si->query_length);
							pta[13][si->query_length] = '\0';
						}
						else {
							pta[13] = NULL;
						}
					}
					sprintf(buf, "%d", mc->status_flags);
					pta[14] = strdup(buf);
				}
				else {
					pta[7] = NULL;
					pta[8] = NULL;
					pta[9] = NULL;
					pta[10] = NULL;
					pta[13] = NULL;
					pta[14] = NULL;
				}
				switch (sess->status) {
				case CONNECTING_SERVER:
					pta[11] = strdup("Connect");
					break;
				case PROCESSING_QUERY:
					if (sess->pause_until > sess->thread->curtime) {
						pta[11] = strdup("Delay");
					}
					else {
						pta[11] = strdup("Query");
					}
					break;
				case WAITING_CLIENT_DATA:
					pta[11] = strdup("Sleep");
					break;
				case CHANGING_USER_SERVER:
					pta[11] = strdup("Changing user server");
					break;
				case CHANGING_USER_CLIENT:
					pta[11] = strdup("Change user client");
					break;
				case RESETTING_CONNECTION:
					pta[11] = strdup("Resetting connection");
					break;
				case RESETTING_CONNECTION_V2:
					pta[11] = strdup("Resetting connection V2");
					break;
				//case CHANGING_SCHEMA:
				//	pta[11] = strdup("InitDB");
				//	break;
				case PROCESSING_STMT_EXECUTE:
					pta[11] = strdup("Execute");
					break;
				case PROCESSING_STMT_PREPARE:
					pta[11] = strdup("Prepare");
					break;
				case CONNECTING_CLIENT:
					pta[11] = strdup("Connecting client");
					break;
				case PINGING_SERVER:
					pta[11] = strdup("Pinging server");
					break;
				case WAITING_SERVER_DATA:
					pta[11] = strdup("Waiting server data");
					break;
				//case CHANGING_CHARSET:
				//	pta[11] = strdup("Changing charset");
				//	break;
				//case CHANGING_AUTOCOMMIT:
				//	pta[11] = strdup("Changing autocommit");
				//	break;
				case SETTING_INIT_CONNECT:
					pta[11] = strdup("Setting init connect");
					break;
					/*
										case SETTING_SQL_LOG_BIN:
																	pta[11]=strdup("Set log bin");
																	break;
										case SETTING_SQL_MODE:
																	pta[11]=strdup("Set SQL mode");
																	break;
										case SETTING_TIME_ZONE:
																	pta[11]=strdup("Set TZ");
																	break;
					*/
				case SETTING_VARIABLE:
				{
					int idx = sess->changing_variable_idx;
					if (idx < SQL_NAME_LAST_HIGH_WM) {
						char buf[128];
						sprintf(buf, "Setting variable %s", mysql_tracked_variables[idx].set_variable_name);
						pta[11] = strdup(buf);
					}
					else {
						pta[11] = strdup("Setting variable");
					}
				}
				break;
				case FAST_FORWARD:
					pta[11] = strdup("Fast forward");
					break;
				case session_status___NONE:
					pta[11] = strdup("None");
					break;
				default:
					sprintf(buf, "%d", sess->status);
					pta[11] = strdup(buf);
					break;
				}
				if (sess->mirror == false) {
					int idx = sess->client_myds->poll_fds_idx;
					unsigned long long last_sent = sess->thread->mypolls.last_sent[idx];
					unsigned long long last_recv = sess->thread->mypolls.last_recv[idx];
					unsigned long long last_time = (last_sent > last_recv ? last_sent : last_recv);
					if (last_time > sess->thread->curtime) {
						last_time = sess->thread->curtime;
					}
					sprintf(buf, "%llu", (sess->thread->curtime - last_time) / 1000);
				}
				else {
					// for mirror session we only consider the start time
					sprintf(buf, "%llu", (sess->thread->curtime - sess->start_time) / 1000);
				}
				pta[12] = strdup(buf);

				pta[15] = NULL;
				if (pgsql_thread___show_processlist_extended) {
					json j;
					sess->generate_proxysql_internal_session_json(j);
					if (pgsql_thread___show_processlist_extended == 2) {
						std::string s = j.dump(4, ' ', false, json::error_handler_t::replace);
						pta[15] = strdup(s.c_str());
					}
					else {
						std::string s = j.dump(-1, ' ', false, json::error_handler_t::replace);
						pta[15] = strdup(s.c_str());
					}
				}
				result->add_row(pta);
				unsigned int k;
				for (k = 0; k < colnum; k++) {
					if (pta[k])
						free(pta[k]);
				}
				free(pta);
			}
		}
		pthread_mutex_unlock(&thr->thread_mutex);
	}
	return result;
}

void PgSQL_Threads_Handler::signal_all_threads(unsigned char _c) {
	unsigned int i;
	unsigned char c = _c;
	if (pgsql_threads == 0) return;
	for (i = 0; i < num_threads; i++) {
		PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
		if (thr == NULL) return; // quick exit, at least one thread is not ready
		int fd = thr->pipefd[1];
		if (write(fd, &c, 1) == -1) {
			proxy_error("Error during write in signal_all_threads()\n");
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
			if (thr == NULL) return; // quick exit, at least one thread is not ready
			int fd = thr->pipefd[1];
			if (write(fd, &c, 1) == -1) {
				proxy_error("Error during write in signal_all_threads()\n");
			}
		}
#endif // IDLE_THREADS
}

void PgSQL_Threads_Handler::kill_connection_or_query(uint32_t _thread_session_id, bool query, char* username) {
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
		thr_id_usr* tu = (thr_id_usr*)malloc(sizeof(thr_id_usr));
		tu->id = _thread_session_id;
		tu->username = strdup(username);
		pthread_mutex_lock(&thr->kq.m);
		if (query) {
			thr->kq.query_ids.push_back(tu);
		}
		else {
			thr->kq.conn_ids.push_back(tu);
		}
		pthread_mutex_unlock(&thr->kq.m);

	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
			thr_id_usr* tu = (thr_id_usr*)malloc(sizeof(thr_id_usr));
			tu->id = _thread_session_id;
			tu->username = strdup(username);
			pthread_mutex_lock(&thr->kq.m);
			if (query) {
				thr->kq.query_ids.push_back(tu);
			}
			else {
				thr->kq.conn_ids.push_back(tu);
			}
			pthread_mutex_unlock(&thr->kq.m);
		}
	}
#endif
	signal_all_threads(0);
}

bool PgSQL_Threads_Handler::kill_session(uint32_t _thread_session_id) {
	bool ret = false;
	unsigned int i;
	signal_all_threads(1);
	for (i = 0; i < num_threads; i++) {
		PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
		pthread_mutex_lock(&thr->thread_mutex);
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
			pthread_mutex_lock(&thr->thread_mutex);
		}
#endif // IDLE_THREADS
	for (i = 0; i < num_threads; i++) {
		PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
		unsigned int j;
		for (j = 0; j < thr->mysql_sessions->len; j++) {
			PgSQL_Session* sess = (PgSQL_Session*)thr->mysql_sessions->pdata[j];
			if (sess->thread_session_id == _thread_session_id) {
				sess->killed = true;
				ret = true;
				goto __exit_kill_session;
			}
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
			unsigned int j;
			for (j = 0; j < thr->mysql_sessions->len; j++) {
				PgSQL_Session* sess = (PgSQL_Session*)thr->mysql_sessions->pdata[j];
				if (sess->thread_session_id == _thread_session_id) {
					sess->killed = true;
					ret = true;
					goto __exit_kill_session;
				}
			}
		}
#endif // IDLE_THREADS
__exit_kill_session:
	for (i = 0; i < num_threads; i++) {
		PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
		pthread_mutex_unlock(&thr->thread_mutex);
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		for (i = 0; i < num_threads; i++) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
			pthread_mutex_unlock(&thr->thread_mutex);
		}
#endif // IDLE_THREADS
	return ret;
}

unsigned long long PgSQL_Threads_Handler::get_total_mirror_queue() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += thr->mirror_queue_mysql_sessions->len; // this is a dirty read
		}
	}
	//this->status_variables.p_gauge_array[p_th_gauge::mirror_queue_lengths]->Set(q);

	return q;
}


/*
unsigned long long PgSQL_Threads_Handler::get_status_variable(
	enum PgSQL_Thread_status_variable v_idx,
	p_th_counter::metric m_idx,
	unsigned long long conv
) {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.stvar[v_idx], 0);
		}
	}
	if (m_idx != p_th_counter::__size) {
		const auto& cur_val = status_variables.p_counter_array[m_idx]->Value();
		double final_val = 0;

		if (conv != 0) {
			final_val = (q - (cur_val * conv)) / conv;
		}
		else {
			final_val = q - cur_val;
		}

		status_variables.p_counter_array[m_idx]->Increment(final_val);
	}
	return q;
}
*/

/*
unsigned long long PgSQL_Threads_Handler::get_status_variable(
	enum PgSQL_Thread_status_variable v_idx,
	p_th_gauge::metric m_idx,
	unsigned long long conv
) {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.stvar[v_idx], 0);
		}
	}
	if (m_idx != p_th_gauge::__size) {
		double final_val = 0;

		if (conv != 0) {
			final_val = q / static_cast<double>(conv);
		}
		else {
			final_val = q;
		}

		status_variables.p_gauge_array[m_idx]->Set(final_val);
	}
	return q;

}
*/

unsigned int PgSQL_Threads_Handler::get_active_transations() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.active_transactions, 0);
		}
	}
	//this->status_variables.p_gauge_array[p_th_gauge::active_transactions]->Set(q);

	return q;
}

#ifdef IDLE_THREADS
unsigned int PgSQL_Threads_Handler::get_non_idle_client_connections() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->mysql_sessions->len, 0);
		}
	}
	//this->status_variables.p_gauge_array[p_th_gauge::client_connections_non_idle]->Set(q);

	return q;
}
#endif // IDLE_THREADS

unsigned long long PgSQL_Threads_Handler::get_pgsql_backend_buffers_bytes() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.stvar[st_var_mysql_backend_buffers_bytes], 0);
		}
	}
	//const auto& cur_val = this->status_variables.p_counter_array[p_th_gauge::mysql_backend_buffers_bytes]->Value();
	//this->status_variables.p_counter_array[p_th_gauge::mysql_backend_buffers_bytes]->Increment(q - cur_val);

	return q;
}

unsigned long long PgSQL_Threads_Handler::get_pgsql_frontend_buffers_bytes() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.stvar[st_var_mysql_frontend_buffers_bytes], 0);
		}
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads)
		for (i = 0; i < num_threads; i++) {
			if (pgsql_threads_idles) {
				PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
				if (thr)
					q += __sync_fetch_and_add(&thr->status_variables.stvar[st_var_mysql_frontend_buffers_bytes], 0);
			}
		}
#endif // IDLE_THREADS
	//this->status_variables.p_counter_array[p_th_gauge::mysql_frontend_buffers_bytes]->Increment(q);

	return q;
}

unsigned long long PgSQL_Threads_Handler::get_pgsql_session_internal_bytes() {
	if ((__sync_fetch_and_add(&status_variables.threads_initialized, 0) == 0) || this->shutdown_) return 0;
	unsigned long long q = 0;
	unsigned int i;
	for (i = 0; i < num_threads; i++) {
		if (pgsql_threads) {
			PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads[i].worker;
			if (thr)
				q += __sync_fetch_and_add(&thr->status_variables.stvar[st_var_mysql_session_internal_bytes], 0);
		}
#ifdef IDLE_THREADS
		if (GloVars.global.idle_threads)
			if (pgsql_threads_idles) {
				PgSQL_Thread* thr = (PgSQL_Thread*)pgsql_threads_idles[i].worker;
				if (thr)
					q += __sync_fetch_and_add(&thr->status_variables.stvar[st_var_mysql_session_internal_bytes], 0);
			}
#endif // IDLE_THREADS
	}
	//this->status_variables.p_gauge_array[p_th_gauge::mysql_session_internal_bytes]->Set(q);

	return q;
}

void PgSQL_Threads_Handler::p_update_metrics() {
	get_total_mirror_queue();
	get_active_transations();
#ifdef IDLE_THREADS
	get_non_idle_client_connections();
#endif // IDLE_THREADS
	get_pgsql_backend_buffers_bytes();
	get_pgsql_frontend_buffers_bytes();
	get_pgsql_session_internal_bytes();
/*
	for (unsigned int i = 0; i < sizeof(PgSQL_Thread_status_variables_counter_array) / sizeof(mythr_st_vars_t); i++) {
		if (PgSQL_Thread_status_variables_counter_array[i].name) {
			get_status_variable(
				PgSQL_Thread_status_variables_counter_array[i].v_idx,
				PgSQL_Thread_status_variables_counter_array[i].m_idx,
				PgSQL_Thread_status_variables_counter_array[i].conv
			);
		}
	}
	// Gauge variables
	for (unsigned int i = 0; i < sizeof(PgSQL_Thread_status_variables_gauge_array) / sizeof(mythr_g_st_vars_t); i++) {
		if (PgSQL_Thread_status_variables_gauge_array[i].name) {
			get_status_variable(
				PgSQL_Thread_status_variables_gauge_array[i].v_idx,
				PgSQL_Thread_status_variables_gauge_array[i].m_idx,
				PgSQL_Thread_status_variables_gauge_array[i].conv
			);
		}
	}
*/
/*
	this->status_variables.p_gauge_array[p_th_gauge::mysql_wait_timeout]->Set(this->variables.wait_timeout);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_ping_interval]->Set(this->variables.monitor_ping_interval / 1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_max_connections]->Set(this->variables.max_connections);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_enabled]->Set(this->variables.monitor_enabled);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_ping_timeout]->Set(this->variables.monitor_ping_timeout / 1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_ping_max_failures]->Set(this->variables.monitor_ping_max_failures);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_aws_rds_topology_discovery_interval]->Set(this->variables.monitor_aws_rds_topology_discovery_interval);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_read_only_interval]->Set(this->variables.monitor_read_only_interval/1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_read_only_timeout]->Set(this->variables.monitor_read_only_timeout/1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_writer_is_also_reader]->Set(this->variables.monitor_writer_is_also_reader);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_replication_lag_group_by_host]->Set(this->variables.monitor_replication_lag_group_by_host);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_replication_lag_interval]->Set(this->variables.monitor_replication_lag_interval / 1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_replication_lag_timeout]->Set(this->variables.monitor_replication_lag_timeout / 1000.0);
	this->status_variables.p_gauge_array[p_th_gauge::mysql_monitor_history]->Set(this->variables.monitor_history / 1000.0);
*/
}

void PgSQL_Thread::Get_Memory_Stats() {
	unsigned int i;
	status_variables.stvar[st_var_mysql_backend_buffers_bytes] = 0;
	status_variables.stvar[st_var_mysql_frontend_buffers_bytes] = 0;
	status_variables.stvar[st_var_mysql_session_internal_bytes] = sizeof(PgSQL_Thread);
	if (mysql_sessions) {
		status_variables.stvar[st_var_mysql_session_internal_bytes] += (mysql_sessions->size) * sizeof(PgSQL_Session*);
		if (epoll_thread == false) {
			for (i = 0; i < mysql_sessions->len; i++) {
				PgSQL_Session* sess = (PgSQL_Session*)mysql_sessions->index(i);
				sess->Memory_Stats();
			}
		}
		else {
			status_variables.stvar[st_var_mysql_frontend_buffers_bytes] += (mysql_sessions->len * QUEUE_T_DEFAULT_SIZE * 2);
			status_variables.stvar[st_var_mysql_session_internal_bytes] += (mysql_sessions->len * sizeof(PgSQL_Connection));
#if !defined(__FreeBSD__) && !defined(__APPLE__)
			status_variables.stvar[st_var_mysql_session_internal_bytes] += ((sizeof(int) + sizeof(int) + sizeof(std::_Rb_tree_node_base)) * mysql_sessions->len);
#else
			status_variables.stvar[st_var_mysql_session_internal_bytes] += ((sizeof(int) + sizeof(int) + 32) * mysql_sessions->len);
#endif
		}
	}
}


PgSQL_Connection* PgSQL_Thread::get_MyConn_local(unsigned int _hid, PgSQL_Session * sess, char* gtid_uuid, uint64_t gtid_trxid, int max_lag_ms) {
	// some sanity check
	if (sess == NULL) return NULL;
	if (sess->client_myds == NULL) return NULL;
	if (sess->client_myds->myconn == NULL) return NULL;
	if (sess->client_myds->myconn->userinfo == NULL) return NULL;
	unsigned int i;
	std::vector<PgSQL_SrvC*> parents; // this is a vector of srvers that needs to be excluded in case gtid_uuid is used
	PgSQL_Connection* c = NULL;
	for (i = 0; i < cached_connections->len; i++) {
		c = (PgSQL_Connection*)cached_connections->index(i);
		if (c->parent->myhgc->hid == _hid && sess->client_myds->myconn->has_same_connection_options(c)) { // options are all identical
			if (
				(gtid_uuid == NULL) || // gtid_uuid is not used
				(gtid_uuid && find(parents.begin(), parents.end(), c->parent) == parents.end()) // the server is currently not excluded
				) {
				PgSQL_Connection* client_conn = sess->client_myds->myconn;
				if (c->requires_RESETTING_CONNECTION(client_conn) == false) { // RESETTING CONNECTION is not required
					unsigned int not_match = 0; // number of not matching session variables
					c->number_of_matching_session_variables(client_conn, not_match);
					if (not_match == 0) { // all session variables match
						if (gtid_uuid) { // gtid_uuid is used
							// we first check if we already excluded this parent (MySQL Server)
							PgSQL_SrvC* mysrvc = c->parent;
							std::vector<PgSQL_SrvC*>::iterator it;
							it = find(parents.begin(), parents.end(), mysrvc);
							if (it != parents.end()) {
								// we didn't exclude this server (yet?)
								bool gtid_found = false;
								if (gtid_found) { // this server has the correct GTID
									c = (PgSQL_Connection*)cached_connections->remove_index_fast(i);
									return c;
								} else {
									parents.push_back(mysrvc); // stop evaluating this server
								}
							}
						} else { // gtid_is not used
							if (max_lag_ms >= 0) {
								if ((unsigned int)max_lag_ms < (c->parent->aws_aurora_current_lag_us / 1000)) {
									status_variables.stvar[st_var_aws_aurora_replicas_skipped_during_query]++;
									continue;
								}
							}
							// return the connection
							c = (PgSQL_Connection*)cached_connections->remove_index_fast(i);
							return c;
						}
					}
					
				}
			}
		}
	}
	return NULL;
}

void PgSQL_Thread::push_MyConn_local(PgSQL_Connection * c) {
	PgSQL_SrvC* mysrvc = NULL;
	mysrvc = (PgSQL_SrvC*)c->parent;
	// reset insert_id #1093
	//c->pgsql->insert_id = 0;
	if (mysrvc->status == MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine == ASYNC_IDLE) {
			cached_connections->add(c);
			return; // all went well
		}
	}
	PgHGM->push_MyConn_to_pool(c);
}

void PgSQL_Thread::return_local_connections() {
	if (cached_connections->len == 0) {
		return;
	}
	/*
		PgSQL_Connection **ca=(PgSQL_Connection **)malloc(sizeof(PgSQL_Connection *)*(cached_connections->len+1));
		unsigned int i=0;
	*/
	//	ca[i]=NULL;
	PgHGM->push_MyConn_to_pool_array((PgSQL_Connection**)cached_connections->pdata, cached_connections->len);
	//	free(ca);
	while (cached_connections->len) {
		cached_connections->remove_index_fast(0);
	}
}

void PgSQL_Thread::Scan_Sessions_to_Kill_All() {
	if (kq.conn_ids.size() + kq.query_ids.size()) {
		Scan_Sessions_to_Kill(mysql_sessions);
	}
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {
		if (kq.conn_ids.size() + kq.query_ids.size()) {
			Scan_Sessions_to_Kill(idle_mysql_sessions);
		}
		if (kq.conn_ids.size() + kq.query_ids.size()) {
			Scan_Sessions_to_Kill(resume_mysql_sessions);
		}
		if (kq.conn_ids.size() + kq.query_ids.size()) {
			pthread_mutex_lock(&myexchange.mutex_idles);
			Scan_Sessions_to_Kill(myexchange.idle_mysql_sessions);
			pthread_mutex_unlock(&myexchange.mutex_idles);
		}
		if (kq.conn_ids.size() + kq.query_ids.size()) {
			pthread_mutex_lock(&myexchange.mutex_resumes);
			Scan_Sessions_to_Kill(myexchange.resume_mysql_sessions);
			pthread_mutex_unlock(&myexchange.mutex_resumes);
		}
	}
#endif
	for (std::vector<thr_id_usr*>::iterator it = kq.conn_ids.begin(); it != kq.conn_ids.end(); ++it) {
		thr_id_usr* t = *it;
		free(t->username);
		free(t);
	}
	for (std::vector<thr_id_usr*>::iterator it = kq.query_ids.begin(); it != kq.query_ids.end(); ++it) {
		thr_id_usr* t = *it;
		free(t->username);
		free(t);
	}
	kq.conn_ids.clear();
	kq.query_ids.clear();
}

void PgSQL_Thread::Scan_Sessions_to_Kill(PtrArray * mysess) {
	for (unsigned int n = 0; n < mysess->len && (kq.conn_ids.size() + kq.query_ids.size()); n++) {
		PgSQL_Session* _sess = (PgSQL_Session*)mysess->index(n);
		bool cont = true;
		for (std::vector<thr_id_usr*>::iterator it = kq.conn_ids.begin(); cont && it != kq.conn_ids.end(); ++it) {
			thr_id_usr* t = *it;
			if (t->id == _sess->thread_session_id) {
				if (_sess->client_myds) {
					if (strcmp(t->username, _sess->client_myds->myconn->userinfo->username) == 0) {
						_sess->killed = true;
					}
				}
				cont = false;
				free(t->username);
				free(t);
				kq.conn_ids.erase(it);
			}
		}
		for (std::vector<thr_id_usr*>::iterator it = kq.query_ids.begin(); cont && it != kq.query_ids.end(); ++it) {
			thr_id_usr* t = *it;
			if (t->id == _sess->thread_session_id) {
				proxy_info("Killing query %d\n", t->id);
				if (_sess->client_myds) {
					if (strcmp(t->username, _sess->client_myds->myconn->userinfo->username) == 0) {
						if (_sess->mybe) {
							if (_sess->mybe->server_myds) {
								_sess->mybe->server_myds->wait_until = curtime;
								_sess->mybe->server_myds->kill_type = 1;
							}
						}
					}
				}
				cont = false;
				free(t->username);
				free(t);
				kq.query_ids.erase(it);
			}
		}
	}
}

#ifdef IDLE_THREADS
void PgSQL_Thread::idle_thread_gets_sessions_from_worker_thread() {
	pthread_mutex_lock(&myexchange.mutex_idles);
	while (myexchange.idle_mysql_sessions->len) {
		PgSQL_Session* mysess = (PgSQL_Session*)myexchange.idle_mysql_sessions->remove_index_fast(0);
		register_session(this, mysess, false);
		PgSQL_Data_Stream* myds = mysess->client_myds;
		mypolls.add(POLLIN, myds->fd, myds, monotonic_time());
		// add in epoll()
		struct epoll_event event;
		memset(&event, 0, sizeof(event)); // let's make valgrind happy
		event.data.u32 = mysess->thread_session_id;
		event.events = EPOLLIN;
		epoll_ctl(efd, EPOLL_CTL_ADD, myds->fd, &event);
		// we map thread_id -> position in mysql_session (end of the list)
		sessmap[mysess->thread_session_id] = mysql_sessions->len - 1;
		//fprintf(stderr,"Adding session %p idx, DS %p idx %d\n",mysess,myds,myds->poll_fds_idx);
	}
	pthread_mutex_unlock(&myexchange.mutex_idles);
}
#endif // IDLE_THREADS

void PgSQL_Thread::handle_mirror_queue_mysql_sessions() {
	while (mirror_queue_mysql_sessions->len) {
		if (__sync_add_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1) > (unsigned int)pgsql_thread___mirror_max_concurrency) {
			__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
			//goto __mysql_thread_exit_add_mirror; // we can't add more mirror sessions at runtime
			return;
		}
		else {
			int idx;
			idx = fastrand() % (mirror_queue_mysql_sessions->len);
			PgSQL_Session* newsess = (PgSQL_Session*)mirror_queue_mysql_sessions->remove_index_fast(idx);
			register_session(this, newsess);
			newsess->handler(); // execute immediately
			if (newsess->status == WAITING_CLIENT_DATA) { // the mirror session has completed
				unregister_session(mysql_sessions->len - 1);
				unsigned int l = (unsigned int)pgsql_thread___mirror_max_concurrency;
				if (mirror_queue_mysql_sessions->len * 0.3 > l) l = mirror_queue_mysql_sessions->len * 0.3;
				if (mirror_queue_mysql_sessions_cache->len <= l) {
					bool to_cache = true;
					if (newsess->mybe) {
						if (newsess->mybe->server_myds) {
							to_cache = false;
						}
					}
					if (to_cache) {
						__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
						mirror_queue_mysql_sessions_cache->add(newsess);
					}
					else {
						delete newsess;
					}
				}
				else {
					delete newsess;
				}
			}
			//newsess->to_process=0;
		}
	}
}

void PgSQL_Thread::handle_kill_queues() {
	pthread_mutex_lock(&kq.m);
	if (kq.conn_ids.size() + kq.query_ids.size()) {
		Scan_Sessions_to_Kill_All();
		maintenance_loop = true;
	}
	pthread_mutex_unlock(&kq.m);
}
