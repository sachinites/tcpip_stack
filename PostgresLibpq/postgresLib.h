#ifndef __POSTGRESLIB__
#define __POSTGRESLIB__

#include <stdint.h>
#include <postgresql/libpq-fe.h>

#define DEFAULT_POSTGRES_SERVER_PORT 5432

#define PGSQL_SUCCESS   0
#define PGSQL_FAILED  -1
#define PGSQL_NOOP  1

/* DB Management APIs*/
PGconn*
postgres_get_user_connection (const char *pg_server_ipaddr, const char *user_name);

int
postgresql_create_new_user (const char *server_ip_addr, const char *user_name);

int
postgresql_create_new_database (const char *server_ip_addr,  const char *db_name) ;

int
postgresql_database_assign_user (PGconn* conn,  const char *user_name, const char *db_name) ;

int
postgresql_delete_user (const char *server_ip_addr,  const char *user_name);

int
postgresql_delete_database (const char *server_ip_addr, const char *db_name);

#endif