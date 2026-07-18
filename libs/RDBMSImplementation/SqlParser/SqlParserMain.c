#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "../uapi/sql_api.h"
#include "../SqlParser/ParserExport.h"

int 
main (int argc, char **argv) {

    clock_t tclk ;
    double time_taken ;
    char err_msg[128];
    char line[MAX_STRING_SIZE];
    rdbms_t *rdbms = rdbms_create ();

    if (!rdbms) {
        fprintf (stderr, "Failed to create RDBMS instance\n");
        return 1;
    }

    while (true) {

        printf ("postgres=# ");

        if (!fgets (line, sizeof (line), stdin)) {
            break;
        }

        if (line[0] == '\n') {
            continue;
        }

        tclk  = clock();

        if (sql_query_exec (rdbms, line, err_msg) == 1) {
            break;
        }

        tclk= clock() - tclk;
        time_taken = ((double)tclk * 1000)/CLOCKS_PER_SEC; 
        printf("%f msec\n", time_taken);
    }

    rdbms_destroy (rdbms);
    return 0;
}
