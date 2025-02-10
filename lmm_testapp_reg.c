#include <stdint.h>
#include "LinuxMemoryManager/mm.h"
#include "lmm_testapp_enums.h"

/* Add Application Hdrs here*/



/* Sample Application Structures */
typedef struct test1_ {

   uint32_t var;
} test1_t;

typedef struct test2_ {

   uint32_t var;
} test2_t;

typedef struct test3_ {

   uint32_t var;
} test3_t;

/* Create static array of vm_page_family_t */

#define MM_REG_STRUCT2(structname) \
    {#structname, sizeof(structname), NULL, {0,0}, structname##_index, 0, 0}

const vm_page_family_t vm_page_family_array[] = 
{
    MM_REG_STRUCT2(test1_t),
    MM_REG_STRUCT2(test2_t),
    MM_REG_STRUCT2(test3_t),
    
    /* Register more application structures here */

    {"nil", 0, NULL, {0, 0}, 0, 0, 0}
};

const vm_page_family_t *
mm_get_page_family(uint32_t index) {

    return &vm_page_family_array[(struct_index_t)index];
}