#ifndef __ENHANCED_IP_ROUTING_TABLE__
#define __ENHANCED_IP_ROUTING_TABLE__

/* Implementation of the Paper : 
    A longest prefix first search tree for IP lookup
    Lih-Chyau Wuu, Tzong-Jye Liu, Kuo-Ming Chen
*/

#include <stdint.h>
#include <stdbool.h>

typedef enum {

    ERT_ENTRY_TYPE_NONE,
    ERT_ENTRY_TYPE0,
    ERT_ENTRY_TYPE1
} ert_entry_type_t;

typedef struct ert_entry_ {

    ert_entry_type_t ert_entry_type;
    uint32_t addr;
    uint8_t mask_len;
    struct ert_entry_ *left;
    struct ert_entry_ *right;
} ert_entry_t;

typedef struct ert_table_ {

    ert_entry_t *root;
} ert_table_t;

bool
ert_entry_add_route(ert_table_t *rt_table, ert_entry_t *rt_entry);

#endif 