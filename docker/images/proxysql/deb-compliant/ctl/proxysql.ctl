Section: database
Priority: optional
Homepage: https://proxysql.com
Standards-Version: 3.9.2

Package: proxysql
Version: PKG_VERSION_CURVER
Maintainer: ProxySQL LLC <info@proxysql.com>
Copyright: copyright
Architecture: PKG_ARCH
Depends: libgnutls28 | libgnutls30, libssl (>= 3.0.0) | libssl3 (>= 3.0.0)
# Changelog: CHANGELOG.md
# Readme: README.md
Files: proxysql /usr/bin/
 etc/proxysql.cnf /etc/
 etc/logrotate.d/proxysql /etc/logrotate.d/
 systemd/system/proxysql-initial.service /lib/systemd/system/
 systemd/system/proxysql.service /lib/systemd/system/
 tools/proxysql_galera_checker.sh /usr/share/proxysql/tools/
 tools/proxysql_galera_writer.pl /usr/share/proxysql/tools/
Description: High performance MySQL and PostgreSQL proxy
 ProxySQL is a fast, reliable MySQL and PostgreSQL proxy with advanced runtime configuration management (virtually no configuration change requires a restart). 
 .
 It features query routing, query caching, query rewriting (for queries generated by ORMs, for example) and is most of the time a drop-in replacement for mysqld and postgres from the point of view of the application. It can be configured and remote controlled through an SQL-compatible admin interface.
File: postinst
 #!/bin/sh -e
 if [ ! -d /var/lib/proxysql ]; then mkdir /var/lib/proxysql ; fi
 if ! id -u proxysql > /dev/null 2>&1; then useradd -r -U -s /bin/false  -d /var/lib/proxysql -c "ProxySQL Server"  proxysql; fi
 chown -R proxysql: /var/lib/proxysql
 chown root:proxysql /etc/proxysql.cnf
 chmod 640 /etc/proxysql.cnf
 if [ -d /run/systemd/system ]; then
     systemctl enable proxysql.service > /dev/null || true
     systemctl --system daemon-reload > /dev/null || true
 fi
