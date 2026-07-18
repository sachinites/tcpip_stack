#include <assert.h>
#include "sql_create.h"
#include "rdbms_ds.h"
#include "Catalog.h"

void 
sql_create_data_destroy (sql_create_data_t *cdata) {

}

key_mdata_t *
sql_construct_table_key_mdata (sql_create_data_t *cdata, int *key_mdata_size) {

    int i, j;
    int primary_key_count = 0;

   for (i = 0; i < cdata->n_cols; i++) {

      if (cdata->column_data[i].is_primary_key) primary_key_count++;
   }

   if (primary_key_count == 0) {
      *key_mdata_size = 0;
      return NULL;
   }

    key_mdata_t *key_mdata = (key_mdata_t *)calloc
         (primary_key_count, sizeof (key_mdata_t));

    for (i = 0, j = 0; i < cdata->n_cols; i++) {

        if (cdata->column_data[i].is_primary_key) {
            key_mdata[j].dtype = cdata->column_data[i].dtype;
            key_mdata[j].size = cdata->column_data[i].dtype_len;
            j++;
        }
    }

    *key_mdata_size = j;
    return key_mdata;
}

 void 
 sql_process_create_query (catalog_t *tcatalog, sql_create_data_t *cdata) {

    assert (tcatalog);
    Catalog_insert_new_table (tcatalog, cdata);
    sql_create_data_destroy(cdata);
 }