#include <string.h>
#include "Catalog.h"
#include "rdbms_ds.h"
#include "rdbms_struct.h"
#include "SqlMexprIntf.h"
#include "sql_utils.h"
#include "qep.h"
#include "sql_join.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

bool
 sql_query_initialize_update_query (qep_struct_t *qep, catalog_t *tcatalog) {

    int i;
    bool rc;
    BPluskey_t bpkey;
    ctable_val_t *ctable_val;
    schema_rec_t *schema_rec;

    if (qep->update.n == 0) return true;

    ctable_val = qep->join.tables[0].ctable_val;
    assert(ctable_val);

    bpkey.key = NULL;
    bpkey.key_size = SQL_COLUMN_NAME_MAX_SIZE;

    for (i = 0; i < qep->update.n; i++) {

        bpkey.key = (void *)qep->update.upd_colmns[i].col_name;
        schema_rec = (schema_rec_t *)rdbms_ds_query (ctable_val->schema_table, &bpkey);
        
        if (!schema_rec) {
            printf ("Error : Column %s does not exist in table %s\n",
                qep->update.upd_colmns[i].col_name, ctable_val->table_name);
            return false;
        }

        if (schema_rec->is_primary_key) {
            printf ("Error : Column %s is a primary key, cannot be updated\n",
                qep->update.upd_colmns[i].col_name);
            return false;
        }

        qep->update.upd_colmns[i].schema_rec = schema_rec;

        rc = sql_resolve_exptree_against_table (
                qep,
                tcatalog,
                qep->update.upd_colmns[i].value_exptree,
                ctable_val,
                0,
                &qep->joined_row_tmplate,
                qep->data_src_lst);

        if (!rc) {
            printf ("Error : Value Expresssion for Column %s could not be resolved against table %s\n",
                qep->update.upd_colmns[i].col_name, ctable_val->table_name);
                return false;
        }
    }

     return true;   
 }

static void 
sql_update_record (void *record, schema_rec_t *schema_rec, dtype_value_t dtype_value) {

    int offset = schema_rec->offset;
    int size = schema_rec->dtype_size;

    switch (schema_rec->dtype) {

        case SQL_INT:
            memcpy ((char *)record + offset, &dtype_value.u.int_val, size);
            break;

        case SQL_DOUBLE:
            memcpy ((char *)record + offset, &dtype_value.u.d_val, size);
            break;

        case SQL_STRING:
            strncpy ((char *)record + offset, dtype_value.u.str_val,  size);
            break;

        case SQL_IPV4_ADDR:
            memcpy ((char *)record + offset, &dtype_value.u.ipv4.ipv4_addr_int, size);
            break;

        case SQL_INTERVAL:
            memcpy ((char *)record + offset, &dtype_value.u.interval.lb, sizeof (dtype_value.u.interval.lb));
            memcpy ((char *)record + offset + sizeof (dtype_value.u.interval.lb), 
                &dtype_value.u.interval.ub, sizeof (dtype_value.u.interval.ub));
            break;
        default:
            assert (0);
    }
}

void 
sql_process_update_query (qep_struct_t *qep) {

    int i;
    int row_no = 0;
    Dtype *dtype;
    dtype_value_t dtype_value;

    while (qep_execute_join (qep)) {

        row_no++;
        
        for (i = 0; i < qep->update.n; i++) {

            dtype = sql_evaluate_exp_tree (qep->update.upd_colmns[i].value_exptree);
            
            dtype_value = DTYPE_GET_VAUE(dtype);

            if (sql_is_dtype_compatible (
                    qep->update.upd_colmns[i].schema_rec->dtype, 
                    dtype_value.dtype) == false) {

                printf ("Error : Value Expression for Column %s is of type %s, expected type is %s\n",
                    qep->update.upd_colmns[i].col_name, 
                    sql_dtype_str(dtype_value.dtype),
                    sql_dtype_str(qep->update.upd_colmns[i].schema_rec->dtype));
                printf ("Error : Update Query aborted\n");
                return;
            }

            sql_update_record (qep->joined_row_tmplate->rec_array[0], 
                qep->update.upd_colmns[i].schema_rec, dtype_value);
        }
    }
    printf ("UPDATE %u\n", row_no);
}

