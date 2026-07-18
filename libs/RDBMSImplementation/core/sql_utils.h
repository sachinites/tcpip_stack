#ifndef __SQL_UTILS__
#define __SQL_UTILS__

#include <string.h>
#include <math.h>
#include "rdbms_struct.h"
#include "../BPlusTreeLib/BPlusTree.h"

typedef struct sql_create_data_ sql_create_data_t;
typedef struct qep_struct_ qep_struct_t;

/* HashTable Setup */
#define HASH_PRIME_CONST    5381

static unsigned int 
hashfromkey(void *key) {

    unsigned char *str = (unsigned char *)key;
    unsigned int hash = HASH_PRIME_CONST;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int 
equalkeys(void *k1, void *k2)
{
    char *ky1 = (char *)k1;
    char *ky2 = (char *)k2;
    int len1 = strlen(ky1);
    int len2 = strlen(ky2);
    if (len1 != len2) return len1 - len2;
    return (0 == memcmp(k1,k2, len1));
}


key_mdata_t *
sql_construct_table_key_mdata (sql_create_data_t *cdata, int *key_mdata_size);
                                  
void *
sql_get_column_value_from_joined_row (joined_row_t *joined_row, qp_col_t *col);

static inline bool 
mexpr_double_is_integer (double d) {

    double int_part = floor (d);
    return int_part == d;
}

void 
string_trim_quotes (std::string str);

qp_col_t *
sql_get_qp_col_by_name (   qp_col_t **qp_col_array, 
                                                        int n, 
                                                        char *name, 
                                                        bool is_alias);

#define QP_COL_NAME(qp_col_t_ptr) \
    ((char *)sql_get_opnd_variable_name (sql_tree_get_root (qp_col_t_ptr->sql_tree)).c_str())

bool
sql_read_interval_values (char *string_fmt,
                                            int *a, int *b);
void 
sql_select_flush_computed_values (qep_struct_t *qep);

bool 
sql_is_dtype_compatible (sql_dtype_t expected_dtype, sql_dtype_t computed_dtype) ;

int 
sql_get_qep_table_index (qep_struct_t *qep, char *table_name);

#endif 
