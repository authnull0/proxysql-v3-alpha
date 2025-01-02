PROXYSQL_PATH=../../../..
PROXYSQL_IDIR=$(PROXYSQL_PATH)/include

DEPS_PATH=$(PROXYSQL_PATH)/deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc

JSON_IDIR=$(DEPS_PATH)/json

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

LIBHTTPSERVER_DIR=$(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR=$(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR=$(LIBHTTPSERVER_DIR)/build/src/.libs/

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR=$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=$(CURL_DIR)/include
CURL_LDIR=$(CURL_DIR)/lib/.libs

DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

PCRE_PATH=$(DEPS_PATH)/pcre/pcre
PCRE_LDIR=$(PCRE_PATH)/.libs

MICROHTTPD_DIR=$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR=$(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR=$(MICROHTTPD_DIR)/microhttpd/.libs

LIBINJECTION_DIR=$(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR=$(LIBINJECTION_DIR)/src
LIBINJECTION_LDIR=$(LIBINJECTION_DIR)/src

libssl_path := $(shell find /usr /usr/local /opt -name "libssl.so" 2>/dev/null | head -n 1)

ifneq ($(libssl_path),)
    SSL_LDIR := $(dir $(libssl_path))
    $(info Found OpenSSL libs at $(SSL_LDIR))
else
    $(error Warning: OpenSSL library not found. exiting, please install openssl.)
endif

ssl_header_path := $(shell find /usr /usr/local /opt -name "ssl.h" -path "*/openssl/*" 2>/dev/null | head -n 1)

ifneq ($(ssl_header_path),)
    SSL_IDIR := $(shell dirname $(ssl_header_path))
    $(info Found OpenSSL headers at $(SSL_IDIR))
else
    $(error Warning: OpenSSL headers not found. exiting, please install openssl.)
endif

EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)
EV_LDIR=$(EV_DIR)/.libs

PROMETHEUS_PATH=$(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR=$(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR=$(PROMETHEUS_PATH)/lib

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

IDIR=$(PROXYSQL_PATH)/include
LDIR=$(PROXYSQL_PATH)/lib
TAP_LIBDIR=$(PROXYSQL_PATH)/test/tap/tap

TAP_DEPS_IDIR=$(CURL_LDIR)
TAP_DEPS_LIBS=$(CURL_LDIR)

ODIR=$(PROXYSQL_PATH)/obj

EXECUTABLE=proxysql

OBJ=$(PROXYSQL_PATH)/proxysql_global.o $(PROXYSQL_PATH)/src/obj/main.o

PROXYLDIR=$(PROXYSQL_PATH)/lib
LIBPROXYSQLAR=$(PROXYSQL_PATH)/lib/libproxysql.a

INCLUDEDIRS=-I../tap -I$(RE2_PATH) -I$(IDIR) -I$(JEMALLOC_IDIR) -I$(SQLITE3_DIR) -I$(LIBHTTPSERVER_IDIR)\
			-I$(CURL_IDIR) -I$(DAEMONPATH_IDIR) -I$(MARIADB_IDIR) -I$(SSL_IDIR) -I$(JSON_IDIR)\
			-I$(LIBCONFIG_IDIR) -I$(PROMETHEUS_IDIR)
LDIRS=-L$(TAP_LIBDIR) -L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR)\
	  -L$(DAEMONPATH_LDIR) -L$(PCRE_LDIR) -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(LIBINJECTION_LDIR)\
	  -L$(CURL_LDIR) -L$(EV_LDIR) -L$(SSL_LDIR) -L$(PROMETHEUS_LDIR)

MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lmariadbclient -lcurl -lssl -lcrypto -Wl,-Bdynamic -lgnutls -lpthread -lm -lz -lrt
STATIC_LIBS= $(SSL_LDIR)/libssl.a $(SSL_LDIR)/libcrypto.a

# Root directory for the deps used for testing purposes
TEST_DEPS=$(JENKINS_SCRIPTS_PATH)/test-scripts/deps
