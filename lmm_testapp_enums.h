#ifndef __LMM_ENUM__
#define __LMM_ENUM__

#define MM_INDEX(structname)  structname##_index

typedef enum struct_index_ {

    MM_INDEX(test1_t),
    MM_INDEX(test2_t),
    MM_INDEX(test3_t)
    /* Add more Application structure Index here */

} struct_index_t;


#endif 