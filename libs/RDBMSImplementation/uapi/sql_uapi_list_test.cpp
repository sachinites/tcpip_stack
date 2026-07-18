#include <stdio.h>
#include <string.h>
#include "sql_api.h"

/*
 * UAPI demo: per-table storage engine selection in one database.
 *
 * The engine is chosen once at CREATE TABLE time via USING:
 *
 *   create table departments (...) using list
 *   create table employees (...) using bplustree
 *
 * All subsequent SQL (INSERT, SELECT, JOIN, UPDATE, DELETE, DROP) is ordinary
 * SQL — no engine argument or API call is needed per statement.
 *
 * API notes:
 *   - Keywords must be lowercase
 *   - Each statement must end with '\n'
 */

static int
run_sql (rdbms_t *rdbms, const char *sql)
{
    char err_msg[256];
    int rc;

    memset (err_msg, 0, sizeof (err_msg));
    printf ("\nSQL> %s", sql);
    fflush (stdout);

    rc = sql_query_exec (rdbms, (char *)sql, err_msg);
    if (rc != 0) {
        printf ("sql_query_exec returned %d", rc);
        if (err_msg[0])
            printf (" (%s)", err_msg);
        printf ("\n");
    }
    fflush (stdout);
    return rc;
}

int
main (int argc, char **argv)
{
    (void)argc;
    (void)argv;

    rdbms_t *rdbms = rdbms_create ();
    if (!rdbms) {
        fprintf (stderr, "rdbms_create failed\n");
        return 1;
    }

    printf ("RDBMS UAPI per-table storage engine demo\n");

    /* Engine specified only here, at CREATE TABLE time */
    run_sql (rdbms,
             "create table departments ("
             "dept_id int primary key, "
             "dept_name varchar(32), "
             "budget double"
             ") using list\n");

    run_sql (rdbms,
             "create table employees ("
             "emp_id int primary key, "
             "emp_name varchar(32), "
             "dept_id int, "
             "salary double"
             ") using bplustree\n");

    run_sql (rdbms, "\\dt\n");

    /* From here on: normal SQL, no engine hints */
    run_sql (rdbms, "insert into departments values (30, 'HR', 90000.0)\n");
    run_sql (rdbms, "insert into departments values (10, 'Engineering', 250000.0)\n");
    run_sql (rdbms, "insert into departments values (20, 'Sales', 180000.5)\n");

    run_sql (rdbms, "insert into employees values (3, 'Carol', 20, 72000.0)\n");
    run_sql (rdbms, "insert into employees values (1, 'Alice', 10, 95000.0)\n");
    run_sql (rdbms, "insert into employees values (2, 'Bob', 10, 87000.5)\n");

    run_sql (rdbms, "select * from departments\n");
    run_sql (rdbms, "select * from employees\n");

    run_sql (rdbms,
             "select e.emp_name, d.dept_name, e.salary "
             "from employees as e, departments as d "
             "where e.dept_id = d.dept_id\n");

    run_sql (rdbms,
             "update employees set salary = salary + 1000.0 where emp_id = 2\n");

    run_sql (rdbms, "delete from departments where dept_id = 30\n");
    run_sql (rdbms, "select * from departments\n");

    run_sql (rdbms,
             "create table bad (id int primary key) using nosuchengine\n");

    run_sql (rdbms, "drop table employees\n");
    run_sql (rdbms, "drop table departments\n");
    run_sql (rdbms, "\\dt\n");

    rdbms_destroy (rdbms);
    printf ("\nPer-table engine demo finished.\n");
    return 0;
}
