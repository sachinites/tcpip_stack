
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <memory.h>
#include <string.h>
#include <string>
#include <assert.h>
#include "sql_utils.h"
#include "sql_insert_into.h"
#include "rdbms_ds.h"
#include "Catalog.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

static bool 
sql_validate_insert_query_data ( catalog_t *TableCatalog, sql_insert_into_data_t *idata) {

    return true;
}

static bool
sql_insert_new_record ( catalog_t *tcatalog, sql_insert_into_data_t *idata) {

    int i;
    BPluskey_t *bpkey_ptr;
    ctable_val_t *ctable_val;
    BPluskey_t bpkey, new_bpkey;

    char *table_name = idata->table_name;

    if (!sql_validate_insert_query_data (tcatalog, idata)) {
        return false;
    }

    ctable_val = (ctable_val_t *)sql_catalog_table_lookup_by_table_name (tcatalog, table_name);

    if (!ctable_val) {
        printf ("Error : Table not found\n");
        return false;
    }

    rdbms_ds_t *schema_table = ctable_val->schema_table;
    rdbms_ds_t *data_table = ctable_val->record_table;

    void *_rec;
    int key_size = 0;
    int rec_size = 0;
    schema_rec_t *rec;

    RDBMS_DS_ITERATE_BEGIN(schema_table, bpkey_ptr, _rec) {
    
        rec = (schema_rec_t *)_rec;

        if (rec->is_primary_key) {
             key_size += rec->dtype_size;
        }
        rec_size += rec->dtype_size;

    } RDBMS_DS_ITERATE_END;

    new_bpkey.key = calloc (1, key_size);
    new_bpkey.key_size = key_size;
    void *record = calloc(1, rec_size);
    int key_offset = 0;

    /* Now fill the key content*/
    i = 0;

    /* We need to iterate in the same order in which columns 
         were specified by the user in create table query */
    while (ctable_val->column_lst[i][0] != '\0') {

        bpkey.key = (void *)ctable_val->column_lst[i];
        bpkey.key_size = SQL_COLUMN_NAME_MAX_SIZE;
        rec = (schema_rec_t *) rdbms_ds_query (schema_table, &bpkey);

        if (!sql_is_dtype_compatible (rec->dtype, idata->sql_values[i].dtype)) {

            printf ("Error : %dth Data Type Mis-Match, Expexted %s, Provided %s for col name %s\n", 
                        i, sql_dtype_str (rec->dtype),  
                        sql_dtype_str (idata->sql_values[i].dtype), 
                        rec->column_name);

            free (new_bpkey.key);
            free(record);
            return false;
        }

        if (rec->is_primary_key) {
    
                switch (rec->dtype) {

                    case SQL_STRING:
                        strncpy((char *)new_bpkey.key + key_offset,
                                idata->sql_values[i].u.str_val,
                                rec->dtype_size);
                        key_offset += rec->dtype_size;
                        break;
                    case SQL_INT:
                        memcpy((char *)new_bpkey.key + key_offset,
                                    (unsigned char *)&idata->sql_values[i].u.int_val,
                                    rec->dtype_size);
                        key_offset += rec->dtype_size;
                        break;
                    case SQL_DOUBLE:
                        memcpy((char *)new_bpkey.key + key_offset,
                                    (unsigned char *)&idata->sql_values[i].u.d_val,
                                    rec->dtype_size);
                        key_offset += rec->dtype_size;
                        break;                
                    case SQL_IPV4_ADDR:
                        /* We store IP Address as integers*/
                        inet_pton(AF_INET,
                                    idata->sql_values[i].u.ipv4_addr_str,
                                (void *)((char *)new_bpkey.key + key_offset));
                        key_offset += rec->dtype_size;
                        break;
                    case SQL_INTERVAL:
                        {
                            memcpy((char *)new_bpkey.key + key_offset,
                                    (unsigned char *)&idata->sql_values[i].u.ival,
                                    rec->dtype_size);
                            key_offset += rec->dtype_size;
                        }
                    break;
                    default:
                        assert(0);
                }
            }
            /* Fill the record material*/
            switch (rec->dtype) {

                case SQL_STRING:
                    strncpy((char *)record + rec->offset,
                            idata->sql_values[i].u.str_val,
                            rec->dtype_size);
                    break;
                case SQL_INT:
                    memcpy((char *)record + rec->offset,
                        (unsigned char *)&idata->sql_values[i].u.int_val,
                        rec->dtype_size);
                    break;            
                case SQL_DOUBLE:
                    memcpy((char *)record + rec->offset,
                        (unsigned char *)&idata->sql_values[i].u.d_val,
                        rec->dtype_size);
                    break;
                case SQL_IPV4_ADDR:
                    /* We store IP Address as integers*/
                    inet_pton(AF_INET,
                            (const char *)idata->sql_values[i].u.ipv4_addr_str,
                            (void *)((char *)record + rec->offset));
                    break;
                case SQL_INTERVAL:
                    memcpy((char *)record + rec->offset,
                        (unsigned char *)&idata->sql_values[i].u.ival,
                        rec->dtype_size);
                    break;
                default:
                    assert(0);
                }
                i++;
    } 

    /* Check for Duplication */
    if (rdbms_ds_query (data_table, &new_bpkey)) {
        free (new_bpkey.key);
        free(record);
        printf ("ERROR:  duplicate key value violates unique constraint \"%s_pkey\"\n", table_name);
        return false;
    }

    /* Now key and records are ready, insert it into data table*/
    bool rc =  (rdbms_ds_insert (data_table, &new_bpkey, record));

    if (!rc) {
        free (new_bpkey.key);
        free(record);
        printf ("Record Insertion Failed\n");
        return false;
    }

    printf ("INSERT 0 1\n");
    return true;
}

void
 sql_insert_into_data_destroy(sql_insert_into_data_t *idata) {

 }

void
 sql_process_insert_query (catalog_t *tcatalog, sql_insert_into_data_t *idata) {

     assert (tcatalog);
     sql_insert_new_record (tcatalog, idata);
     sql_insert_into_data_destroy(idata);
 }

