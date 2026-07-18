#include <stdbool.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "rdbms_struct.h"
#include "sql_const.h"
#include "sql_utils.h"
#include "sql_create.h"
#include "rdbms_ds.h"
#include "Catalog.h"

extern int cprintf (const char *format, ...);
#define printf cprintf

extern  int 
rdbms_key_comp_fn (BPluskey_t *key_1, BPluskey_t *key_2, key_mdata_t *key_mdata, int size);

static void 
schema_table_record_free (void *ptr) {

    schema_rec_t *schema_rec = (schema_rec_t *)ptr;
    free (schema_rec);
}

/* Free a catalog table value: tear down its nested storage then the value. */
static void
ctable_val_free (ctable_val_t *ctable_val) {

    if (!ctable_val) return;

    if (ctable_val->schema_table) {
        rdbms_ds_destroy (ctable_val->schema_table);
        ctable_val->schema_table = NULL;
    }
    if (ctable_val->record_table) {
        rdbms_ds_destroy (ctable_val->record_table);
        ctable_val->record_table = NULL;
    }
    free (ctable_val);
}

/* ---- Hardcoded catalog (fixed array of table values) ---- */

catalog_t *
catalog_create (void) {

    return (catalog_t *) calloc (1, sizeof (catalog_t));
}

void
catalog_destroy (catalog_t *catalog) {

    int i;

    if (!catalog) return;

    for (i = 0; i < catalog->count; i++) {
        ctable_val_free (catalog->entries[i]);
        catalog->entries[i] = NULL;
    }
    free (catalog);
}

ctable_val_t *
catalog_lookup (catalog_t *catalog, const char *table_name) {

    int i;

    if (!catalog || !table_name) return NULL;

    for (i = 0; i < catalog->count; i++) {
        if (strncmp (catalog->entries[i]->table_name,
                     table_name, SQL_TABLE_NAME_MAX_SIZE) == 0) {
            return catalog->entries[i];
        }
    }
    return NULL;
}

bool
catalog_add (catalog_t *catalog, ctable_val_t *ctable_val) {

    if (!catalog || !ctable_val) return false;
    if (catalog->count >= SQL_MAX_TABLES_IN_CATALOG) return false;
    if (catalog_lookup (catalog, ctable_val->table_name)) return false;

    catalog->entries[catalog->count++] = ctable_val;
    return true;
}

bool
catalog_remove (catalog_t *catalog, const char *table_name) {

    int i, j;

    if (!catalog || !table_name) return false;

    for (i = 0; i < catalog->count; i++) {

        if (strncmp (catalog->entries[i]->table_name,
                     table_name, SQL_TABLE_NAME_MAX_SIZE) == 0) {

            ctable_val_free (catalog->entries[i]);

            for (j = i; j < catalog->count - 1; j++) {
                catalog->entries[j] = catalog->entries[j + 1];
            }
            catalog->entries[catalog->count - 1] = NULL;
            catalog->count--;
            return true;
        }
    }
    return false;
}

/* ---- Table creation ---- */

static void
Catalog_create_schema_table_records (
            rdbms_ds_t *schema_table,
            sql_create_data_t *cdata) {

    int i;
    int offset = 0;
    BPluskey_t bpkey_tmplate;
    schema_rec_t *schema_rec;

    for (i = 0; i < cdata->n_cols; i++) {

        /* Setup the key */
        bpkey_tmplate.key = (void *)calloc(1, SQL_COLUMN_NAME_MAX_SIZE);
        strncpy( (char *)bpkey_tmplate.key, 
                      cdata->column_data[i].col_name,
                      SQL_COLUMN_NAME_MAX_SIZE);
        bpkey_tmplate.key_size = SQL_COLUMN_NAME_MAX_SIZE;

        /* Setup the value (a.k.a record)*/
        schema_rec = (schema_rec_t *)calloc(1, sizeof(schema_rec_t));
        strncpy(schema_rec->column_name,  
                     cdata->column_data[i].col_name,
                     SQL_COLUMN_NAME_MAX_SIZE);
        schema_rec->dtype = cdata->column_data[i].dtype;
        schema_rec->dtype_size = cdata->column_data[i].dtype_len;
        schema_rec->offset = offset;
        offset += cdata->column_data[i].dtype_len;
        schema_rec->is_primary_key = cdata->column_data[i].is_primary_key;

        /* Insert into Schema table now */
        assert (rdbms_ds_insert (schema_table, &bpkey_tmplate, (void *)schema_rec));
    }
}

bool 
Catalog_insert_new_table (catalog_t *catalog, sql_create_data_t *cdata) {

    int i;
    const char *engine;

    assert (catalog);

    /* A table with the same name must not already exist */
    if (catalog_lookup (catalog, cdata->table_name)) {
        printf ("Error : Table Already Exist\n");
        return false;
    }

    /* Resolve per-table engine (NULL => registry default). */
    engine = cdata->engine_name[0] ? cdata->engine_name : NULL;
    if (engine && !rdbms_ds_lookup (engine)) {
        printf ("Error : Unknown storage engine '%s'\n", engine);
        return false;
    }

    /* Let us create a VALUE for the catalog, so that we can attempt insertion
       as early as possible. This helps us rewind if there is any error*/
    ctable_val_t *ctable_val = (ctable_val_t *)calloc (1, sizeof (ctable_val_t));
    strncpy(ctable_val->table_name, cdata->table_name, SQL_TABLE_NAME_MAX_SIZE);
    ctable_val->schema_table = NULL;
    ctable_val->record_table = NULL;

     for (i = 0; i < cdata->n_cols; i++) {
        
        strncpy (ctable_val->column_lst[i],
            cdata->column_data[i].col_name,
            SQL_COLUMN_NAME_MAX_SIZE );
     }

     /* Represent the end of array, be careful !*/
     ctable_val->column_lst[cdata->n_cols][0] = '\0';     

    /* Now create a Schema table for this new table. Schema table stores all the
       attributes and details of an RDBMS table.*/
    static key_mdata_t key_mdata2[] = {{SQL_STRING, SQL_COLUMN_NAME_MAX_SIZE}};

    rdbms_ds_config_t schema_cfg;
    schema_cfg.cmp_fn = rdbms_key_comp_fn;
    schema_cfg.free_fn = schema_table_record_free;
    schema_cfg.key_mdata = key_mdata2;
    schema_cfg.key_mdata_size = sizeof (key_mdata2) / sizeof (key_mdata2[0]);
    schema_cfg.max_children = SQL_BTREE_MAX_CHILDREN_SCHEMA_TABLE;

    rdbms_ds_t *schema_table = rdbms_ds_create (engine, &schema_cfg);
    if (!schema_table) {
        free (ctable_val);
        if (engine) {
            printf ("Error : Failed to create schema store for engine '%s'\n", engine);
        } else {
            printf ("Error : Failed to create schema store\n");
        }
        return false;
    }

    /* Schema table has been created, now insert records in it. Each record is of the type : 
       key::  <column name>   value :: <schema_rec_t >  */
     Catalog_create_schema_table_records (schema_table, cdata);

    /* Construct key meta data for this Table Schema*/
    int key_mdata_size3;
    key_mdata_t *key_mdata3 = sql_construct_table_key_mdata (cdata, &key_mdata_size3);

    if (!key_mdata3) {
        rdbms_ds_destroy (schema_table);
        free(ctable_val);
        printf ("Error : Table Must have atleast one primary key\n");
        return false;
    }

    /* Now make the actual rdbms table to hold records */
    rdbms_ds_config_t record_cfg;
    record_cfg.cmp_fn = rdbms_key_comp_fn;
    record_cfg.free_fn = free;
    record_cfg.key_mdata = key_mdata3;
    record_cfg.key_mdata_size = key_mdata_size3;
    record_cfg.max_children = SQL_BTREE_MAX_CHILDREN_RDBMS_TABLE;

    rdbms_ds_t *record_table = rdbms_ds_create (engine, &record_cfg);
    if (!record_table) {
        rdbms_ds_destroy (schema_table);
        free (ctable_val);
        if (engine) {
            printf ("Error : Failed to create record store for engine '%s'\n", engine);
        } else {
            printf ("Error : Failed to create record store\n");
        }
        return false;
    }

    /* Now store the Schema Table and RDBMS table as VALUE of the catalog*/
    ctable_val->schema_table = schema_table;
    ctable_val->record_table = record_table;
    strncpy (ctable_val->engine_name,
             schema_table->ops->name,
             SQL_STORAGE_ENGINE_NAME_MAX);

    catalog_add (catalog, ctable_val);
    printf ("CREATE TABLE\n");
    return true;
}

void 
sql_show_table_catalog (catalog_t *TableCatalog) {

    int i;
    int rows = 0;
    ctable_val_t *ctable_val;
    
    assert (TableCatalog);

    printf ("           List of relations\n");
    printf (" Schema    |           Name           | Type  | Engine     | Owner  \n");
    printf ("-----------+--------------------------+-------+------------+--------------\n");

    for (i = 0; i < TableCatalog->count; i++) {

        ctable_val = TableCatalog->entries[i];
        printf (" public    | %-23s  | table | %-10s | postgres  \n",
                ctable_val->table_name, ctable_val->engine_name);
        rows++;
    }

    printf ("(%d rows)\n", rows);
}

ctable_val_t *
sql_catalog_table_lookup_by_table_name (catalog_t *TableCatalog, 
                                                                      char *entity_name) {

    return catalog_lookup (TableCatalog, entity_name);
}
