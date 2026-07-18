#include <assert.h>
#include <string.h>
#include <memory.h>
#include "../SqlParser/SqlEnums.h"
#include "../BPlusTreeLib/BPlusTree.h"

int 
rdbms_key_comp_fn (BPluskey_t *key_1, BPluskey_t *key_2, key_mdata_t *key_mdata, int size) {

    int i , rc;
    int dsize;
    int offset = 0;

    sql_dtype_t dtype;

    if (!key_1 || !key_1->key || !key_1->key_size) return 1;
    if (!key_2 || !key_2->key || !key_2->key_size) return -1;

    char *key1 = (char *)key_1->key;
    char *key2 = (char *)key_2->key;

    if (!key_mdata || !size) {
        /* Implement a general memcmp function */
        assert (key_1->key_size == key_2->key_size);
        rc = memcmp (key1, key2, key_1->key_size);
        if (rc > 0) return -1;
        if (rc < 0) return 1;
        return 0; 
    }

    for (i = 0; i < size ; i++) {

        dtype = (sql_dtype_t)(key_mdata)[i].dtype;
        dsize = (key_mdata)[i].size;

        switch (dtype) {

            case SQL_STRING:
                rc = strncmp (key1 + offset, key2 + offset, dsize);
                if (rc < 0) return 1;
                if (rc > 0) return -1;
                offset += dsize;
                break;
            case  SQL_INT:
                {
                    int *n1 = (int *)(key1 + offset);
                    int *n2 = (int *)(key2 + offset);
                    if (*n1 < *n2) return 1;
                    if (*n1 > *n2) return -1;
                    offset += dsize;
                }
                break;
            case SQL_IPV4_ADDR:
                {
                    uint32_t *n1 = (uint32_t *)(key1 + offset);
                    uint32_t *n2 = (uint32_t *)(key2 + offset);
                    if (*n1 < *n2) return 1;
                    if (*n1 > *n2) return -1;
                    offset += dsize;
                }
                break;
            case SQL_DOUBLE:
              {
                    double *n1 = (double *)(key1 + offset);
                    double*n2 = (double *)(key2 + offset);
                    if (*n1 < *n2) return 1;
                    if (*n1 > *n2) return -1;
                    offset += dsize;
                }
                break;
            case SQL_INTERVAL:
            {
                    int *n11 = (int *)(key1 + offset);
                    int *n12 = (int *)(key1 + offset + sizeof(int));
                    int *n21 = (int *)(key2 + offset);
                    int *n22 = (int *)(key2 + offset + sizeof(int));
                    if (*n11 == *n21 && *n12 == *n22){ 
                        offset += dsize; 
                    }
                    else {
                        return -1;
                    }
            }
            break;
            default:
                break;
        }
    }
    return 0;
}