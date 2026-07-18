#ifndef __SQL_API__
#define __SQL_API__

#include "rdbms_ctx.h"

class Dtype;

typedef void (*sql_record_reader_fn_ptr)(void *, std::vector<Dtype *> *); 

rdbms_t *
rdbms_create (void);

void
rdbms_destroy (rdbms_t *rdbms);

/* Returns 0 on success, -1 on error, 1 on quit (REPL \q). */
int
sql_query_exec (rdbms_t *rdbms, char *sql_query, char *err_msg);

#endif
