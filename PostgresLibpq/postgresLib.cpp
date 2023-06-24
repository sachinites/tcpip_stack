#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include <stdbool.h>
#include "../CLIBuilder/libcli.h"
#include "postgresLib.h"

static bool log = false;

PGconn *
postgres_get_user_connection(const char *pg_server_ipaddr, const char *user_name)
{

    unsigned char sql_string[128];

    sprintf((char *)sql_string,
            "host = %s user = %s",
            pg_server_ipaddr ? pg_server_ipaddr : "localhost", user_name);

    PGconn *conn = PQconnectdb(sql_string);

    if (PQstatus(conn) == CONNECTION_OK)
    {

        return conn;
    }
    return NULL;
}

int postgresql_create_new_user(const char *server_ip_addr, const char *user_name)
{

    PGresult *sql_query_result;
    unsigned char sql_string[128];

    // Connect to the database server
    PGconn *conn = postgres_get_user_connection(server_ip_addr, "postgres");

    if (!conn)
    {
        if (log) {
        cprintf("DBServer : %s : Connection Failed\n",
               server_ip_addr ? server_ip_addr : "localhost");
        }
        return PGSQL_FAILED;
    }

    if (log) {
        cprintf("DBServer : %s : Connection Successful\n",
           server_ip_addr ? server_ip_addr : "localhost");
    }

    /* Check if the user already exist */
    sprintf((char *)sql_string, "select * from pg_roles where rolname = '%s'", user_name);
    sql_query_result = PQexec(conn, sql_string);

    // Count the number of result, it must be 0 if not exist, else 1
    if (PQntuples(sql_query_result) == 1)
    {
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_NOOP;
    }

    // SQL command to create the new user
    sprintf((char *)sql_string, "create user %s with password '%s'",
            user_name, user_name);

    // Execute the SQL command to create the new user
    sql_query_result = PQexec(conn, sql_string);

    // Check if the command was successful
    if (PQresultStatus(sql_query_result) != PGRES_COMMAND_OK)
    {
        if (log) {
        cprintf("DBServer : %s : Failed to create user %s, error code = %d\n",
               server_ip_addr ? server_ip_addr : "localhost",
               user_name, PQresultStatus(sql_query_result));
        }
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_FAILED;
    }

    if (log) {
        cprintf("DBServer : %s : User %s Created Successfully with password %s\n",
           server_ip_addr ? server_ip_addr : "localhost",
           user_name, user_name);
    }
    return PGSQL_SUCCESS;
}

int postgresql_create_new_database(const char *server_ip_addr, const char *db_name)
{

    PGresult *sql_query_result;
    unsigned char sql_string[128];

    // Connect to the database server
    PGconn *conn = postgres_get_user_connection(server_ip_addr, "postgres");

    if (!conn)
    {
        if (log) {
            cprintf("DBServer : %s : Connection Failed\n",
               server_ip_addr ? server_ip_addr : "localhost");
        }
        return PGSQL_FAILED;
    }

    /* Check if the database already exist */
    sprintf((char *)sql_string, "select * from pg_database where datname = '%s'", db_name);
    sql_query_result = PQexec(conn, sql_string);

    // Count the number of result, it must be 0 if not exist, else 1
    if (PQntuples(sql_query_result) == 1)
    {
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_NOOP;
    }

    // SQL command to create the new database
    sprintf((char *)sql_string, "create database %s", db_name);

    // Execute the SQL command to create the new user
    sql_query_result = PQexec(conn, sql_string);

    // Check if the command was successful
    if (PQresultStatus(sql_query_result) != PGRES_COMMAND_OK)
    {
        if (log) {
            cprintf("Failed to create database %s, error code = %d\n",
               db_name, PQresultStatus(sql_query_result));
        }
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_FAILED;
    }

    if (log) {
        cprintf("Database %s Created Successfully\n", db_name);
    }
    PQclear(sql_query_result);
    PQfinish(conn);
    return PGSQL_SUCCESS;
}

int postgresql_database_assign_user(PGconn *conn, const char *user_name, const char *db_name)
{

    PGresult *sql_query_result;
    unsigned char sql_string[128];

    // GRANT ALL PRIVILEGES ON DATABASE yourdbname TO youruser;
    sprintf(sql_string, "grant all privileges on database %s to %s", db_name, user_name);
    sql_query_result = PQexec(conn, sql_string);

    if (PQresultStatus(sql_query_result) == PGRES_COMMAND_OK)
    {
        PQclear(sql_query_result);
        return PGSQL_SUCCESS;
    }

    PQclear(sql_query_result);
    return PGSQL_FAILED;
}

int postgresql_delete_user(const char *server_ip_addr, const char *user_name)
{

    PGresult *sql_query_result;
    unsigned char sql_string[128];

    PGconn *conn = postgres_get_user_connection(server_ip_addr, "postgres");
    assert(conn);

    // check if the user exist or not
    sprintf((char *)sql_string, "select * from pg_roles where rolname = '%s'", user_name);
    sql_query_result = PQexec(conn, sql_string);

    // Count the number of result, it must be 0 if not exist, else 1
    if (PQntuples(sql_query_result) == 0)
    {
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_NOOP;
    }

    // SQL command to delete the user
    sprintf((char *)sql_string, "drop user %s", user_name);

    // Execute the SQL command to delete the user
    sql_query_result = PQexec(conn, sql_string);

    // Check if the command was successful
    if (PQresultStatus(sql_query_result) != PGRES_COMMAND_OK)
    {
        if (log) {
            cprintf("DBServer : %s : Failed to delete user %s, error code = %d\n",
               server_ip_addr ? server_ip_addr : "localhost",
               user_name, PQresultStatus(sql_query_result));
        }
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_FAILED;
    }

    PQclear(sql_query_result);
    PQfinish(conn);
    return PGSQL_SUCCESS;
}

int postgresql_delete_database(const char *server_ip_addr, const char *db_name)
{

    PGresult *sql_query_result;
    unsigned char sql_string[192];

    PGconn *conn = postgres_get_user_connection(server_ip_addr, "postgres");
    assert(conn);

    // check if the database exist or not
    sprintf((char *)sql_string, "select * from pg_database where datname = '%s'", db_name);
    sql_query_result = PQexec(conn, sql_string);

    // Count the number of result, it must be 0 if not exist, else 1
    if (PQntuples(sql_query_result) == 0)
    {
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_NOOP;
    }

    /* Before deleting the database, you first need to terminate all active connections to the database. 
      You can use the following command to terminate all connections to a database:*/
      sprintf((char *)sql_string, "select pg_terminate_backend (pg_stat_activity.pid)"
                    "from pg_stat_activity where pg_stat_activity.datname = '%s'", db_name);

    sql_query_result = PQexec(conn, sql_string);
    PQclear(sql_query_result);

    // SQL command to delete the database
    sprintf((char *)sql_string, "drop database %s", db_name);

    // Execute the SQL command to delete the user
    sql_query_result = PQexec(conn, sql_string);

    // Check if the command was successful
    if (PQresultStatus(sql_query_result) != PGRES_COMMAND_OK)
    {
        if (log) {
            cprintf("DBServer : %s : Failed to delete database %s, error code = %d\n",
               server_ip_addr ? server_ip_addr : "localhost",
               db_name, PQresultStatus(sql_query_result));
        }
        PQclear(sql_query_result);
        PQfinish(conn);
        return PGSQL_FAILED;
    }

    PQclear(sql_query_result);
    PQfinish(conn);
    return PGSQL_SUCCESS;
}

#if 0
int
main(int argc , char **argv) {

    int rc;

    rc = postgresql_create_new_user(NULL, "vm1");

    switch (rc) {
    case PGSQL_FAILED:
        cprintf ("Create new User : Operation Failed\n");
        break;
    case PGSQL_NOOP:
        cprintf ("Create new User : User Already Exist\n");
        break;
    case PGSQL_SUCCESS:
        cprintf ("Create new User : User Created Successfully\n");
        break;
    default: ;
    }

    rc = postgresql_create_new_database (NULL, "vm1db");
    switch (rc) {
    case PGSQL_FAILED:
        cprintf ("Create new DB : Operation Failed\n");
        break;
    case PGSQL_NOOP:
        cprintf ("Create new DB : DB Already Exist\n");
        break;
    case PGSQL_SUCCESS:
        cprintf ("Create new DB : DB Created Successfully\n");
        break;
    default: ;
    }
#if 0
    PGconn* conn = postgres_get_user_connection ( NULL, "postgres");
    assert(conn);
    rc = postgresql_database_assign_user (conn, "vm1", "vm1db");
    PQfinish(conn);
    switch (rc) {
    case PGSQL_FAILED:
        cprintf ("Assign DB to new User : Operation Failed\n");
        break;
    case PGSQL_NOOP:
        cprintf ("Assign DB to new User : No Op\n");
        break;
    case PGSQL_SUCCESS:
        cprintf ("Assign DB to new User : Assignment Successfully\n");
        break;
    default: ;
    }
#endif 

    rc = postgresql_delete_database(NULL, "vm1db");

    switch (rc) {
    case PGSQL_FAILED:
        cprintf ("Delete DB : Operation Failed\n");
        break;
    case PGSQL_NOOP:
        cprintf ("Delete DB : DB Do Not Exist\n");
        break;
    case PGSQL_SUCCESS:
        cprintf ("Delete DB : DB Deleted Successfully\n");
        break;
    default: ;
    }

    rc = postgresql_delete_user(NULL, "vm1");

    switch (rc) {
    case PGSQL_FAILED:
        cprintf ("Delete User : Operation Failed\n");
        break;
    case PGSQL_NOOP:
        cprintf ("Delete User : User Do Not Exist\n");
        break;
    case PGSQL_SUCCESS:
        cprintf ("Delete User : User Deleted Successfully\n");
        break;
    default: ;
    }    

    return 0;
}
#endif
