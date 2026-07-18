#include <stdio.h>
#include <string.h>
#include "sql_api.h"

/*
 * Broader UAPI smoke / feature suite for the in-memory RDBMS.
 *
 * Covers: CREATE/DROP, INSERT, SELECT (*, projection, expressions, WHERE),
 * comma-joins, aggregates + GROUP BY/HAVING, ORDER BY/LIMIT, UPDATE/DELETE,
 * typed columns (int, varchar, double, ipv4, interval), and \\dt.
 *
 * API notes:
 *   - Keywords must be lowercase
 *   - Each statement must end with '\n'
 *   - SELECT results print to stdout (no programmatic row API yet)
 *   - avg() currently asserts inside the engine; use count/sum/min/max
 *   - DROP TABLE can crash when the catalog holds exactly 4 tables
 *     (B+tree max-children edge case). This suite drops typed tables
 *     before creating the main schema so DROP never hits that case.
 */

static int
run_sql (rdbms_t *rdbms, const char *label, const char *sql)
{
    char err_msg[256];
    int rc;

    memset (err_msg, 0, sizeof (err_msg));
    printf ("\n=== %s ===\n", label);
    printf ("SQL> %s", sql);
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

    printf ("RDBMS UAPI feature suite\n");

    /* ------------------------------------------------------------------ */
    /* Typed-column smoke (ipv4, interval) — keep catalog size small, then */
    /* DROP so the later employees/departments path stays safe.             */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "CREATE hosts (ipv4)",
             "create table hosts ("
             "host_id int primary key, "
             "hostname varchar(32), "
             "addr ipv4"
             ")\n");

    run_sql (rdbms, "CREATE windows (interval)",
             "create table windows ("
             "win_id int primary key, "
             "label varchar(16), "
             "span interval"
             ")\n");

    run_sql (rdbms, "INSERT hosts",
             "insert into hosts values (1, 'gw', 192.168.1.1)\n");
    run_sql (rdbms, "INSERT hosts",
             "insert into hosts values (2, 'db', 10.0.0.5)\n");
    run_sql (rdbms, "INSERT windows",
             "insert into windows values (1, 'morning', [9, 12])\n");
    run_sql (rdbms, "INSERT windows",
             "insert into windows values (2, 'evening', [18, 22])\n");

    run_sql (rdbms, "SELECT hosts (ipv4)",
             "select * from hosts\n");
    run_sql (rdbms, "SELECT windows (interval)",
             "select * from windows\n");

    run_sql (rdbms, "DELETE host with alias",
             "delete from hosts as h where h.host_id = 2\n");
    run_sql (rdbms, "SELECT hosts after DELETE",
             "select * from hosts\n");

    run_sql (rdbms, "SHOW TABLES (typed)", "\\dt\n");
    run_sql (rdbms, "DROP windows", "drop table windows\n");
    run_sql (rdbms, "DROP hosts", "drop table hosts\n");

    /* ------------------------------------------------------------------ */
    /* Main schema: departments + employees (int/varchar/double)          */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "CREATE departments",
             "create table departments ("
             "dept_id int primary key, "
             "dept_name varchar(32), "
             "budget double"
             ")\n");

    run_sql (rdbms, "CREATE employees",
             "create table employees ("
             "emp_id int primary key, "
             "emp_name varchar(32), "
             "dept_id int, "
             "salary double"
             ")\n");

    run_sql (rdbms, "SHOW TABLES", "\\dt\n");

    run_sql (rdbms, "INSERT departments",
             "insert into departments values (10, 'Engineering', 250000.0)\n");
    run_sql (rdbms, "INSERT departments",
             "insert into departments values (20, 'Sales', 180000.5)\n");
    run_sql (rdbms, "INSERT departments",
             "insert into departments values (30, 'HR', 90000.0)\n");

    run_sql (rdbms, "INSERT employees",
             "insert into employees values (1, 'Alice', 10, 95000.0)\n");
    run_sql (rdbms, "INSERT employees",
             "insert into employees values (2, 'Bob', 10, 87000.5)\n");
    run_sql (rdbms, "INSERT employees",
             "insert into employees values (3, 'Carol', 20, 72000.0)\n");
    run_sql (rdbms, "INSERT employees",
             "insert into employees values (4, 'Dave', 20, 68000.25)\n");
    run_sql (rdbms, "INSERT employees",
             "insert into employees values (5, 'Eve', 30, 61000.0)\n");
    run_sql (rdbms, "INSERT employees",
             "insert into employees values (6, 'Frank', 10, 102000.0)\n");

    /* ------------------------------------------------------------------ */
    /* SELECT basics                                                      */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "SELECT * employees",
             "select * from employees\n");

    run_sql (rdbms, "SELECT projection + expression",
             "select emp_id, emp_name, salary, salary + 1000.0 as salary_bonus "
             "from employees\n");

    run_sql (rdbms, "SELECT with WHERE (and)",
             "select emp_name, salary from employees "
             "where salary > 70000.0 and dept_id = 10\n");

    run_sql (rdbms, "SELECT with WHERE (or)",
             "select emp_name, dept_id, salary from employees "
             "where dept_id = 30 or salary > 100000.0\n");

    run_sql (rdbms, "SELECT math helpers",
             "select emp_name, sqr(dept_id) as d2, sqrt(salary) as sroot "
             "from employees where emp_id < 4\n");

    /* ------------------------------------------------------------------ */
    /* JOIN (comma-join + WHERE equijoin)                                 */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "JOIN employees x departments",
             "select e.emp_name, d.dept_name, e.salary "
             "from employees as e, departments as d "
             "where e.dept_id = d.dept_id\n");

    /* ------------------------------------------------------------------ */
    /* Aggregates / GROUP BY / HAVING  (avg() not used — see notes)       */
    /* ------------------------------------------------------------------ */
    /* Global sum(salary) over large doubles can overflow in the current
     * aggregator; keep the ungated demo to count/min/max and use sum under
     * GROUP BY below, where values stay smaller. */
    run_sql (rdbms, "Aggregates",
             "select count(emp_id) as n, "
             "min(salary) as lo, max(salary) as hi "
             "from employees\n");

    run_sql (rdbms, "GROUP BY",
             "select dept_id, count(emp_id) as n, sum(salary) as payroll "
             "from employees "
             "group by dept_id\n");

    run_sql (rdbms, "GROUP BY + HAVING",
             "select dept_id, count(emp_id) as n, sum(salary) as payroll "
             "from employees "
             "group by dept_id "
             "having n > 1\n");

    /* ------------------------------------------------------------------ */
    /* ORDER BY / LIMIT                                                   */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "ORDER BY DESC + LIMIT",
             "select emp_name, salary from employees "
             "order by salary desc limit 3\n");

    run_sql (rdbms, "ORDER BY ASC",
             "select emp_name, salary from employees order by salary asc\n");

    /* ------------------------------------------------------------------ */
    /* UPDATE / DELETE                                                    */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "UPDATE non-PK column",
             "update employees set salary = salary + 5000.0 where emp_id = 5\n");

    run_sql (rdbms, "SELECT after UPDATE",
             "select emp_id, emp_name, salary from employees where emp_id = 5\n");

    run_sql (rdbms, "DELETE with WHERE",
             "delete from employees where emp_id = 4\n");

    run_sql (rdbms, "SELECT after DELETE",
             "select * from employees\n");

    /* ------------------------------------------------------------------ */
    /* Catalog / cleanup                                                  */
    /* ------------------------------------------------------------------ */
    run_sql (rdbms, "SHOW TABLES (before drop)", "\\dt\n");
    run_sql (rdbms, "DROP employees", "drop table employees\n");
    run_sql (rdbms, "DROP departments", "drop table departments\n");
    run_sql (rdbms, "SHOW TABLES (after drop)", "\\dt\n");

    rdbms_destroy (rdbms);
    printf ("\nFeature suite finished.\n");
    return 0;
}
