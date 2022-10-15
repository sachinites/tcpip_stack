#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "uapi_mm.h"

typedef struct emp_ {

    char name[32];
    uint32_t emp_id;
} emp_t;

typedef struct student_ {

    char name[32];
    uint32_t rollno;
    uint32_t marks_phys;
    uint32_t marks_chem;
    uint32_t marks_maths;
    struct student_ *next;
} student_t;

int
main(int argc, char **argv){

    mm_init();
    MM_REG_STRUCT(0, emp_t);
    MM_REG_STRUCT(0, student_t);

    #if 0
    mm_print_registered_page_families(0);
    mm_print_memory_usage(0, 0);
    mm_print_block_usage(0);
    char *buff1 = XCALLOC_BUFF(0, 32);
    char *buff2 = XCALLOC_BUFF(0, 32);
    assert(buff1);
    assert(buff2);
    mm_print_variable_buffers(0);
    xfree(buff1);
    xfree(buff2);
    mm_print_variable_buffers(0);
    #endif
#if 0
    mm_print_memory_usage(0);
    mm_print_block_usage();
#endif

    emp_t *emp1 = XCALLOC(0, 1, emp_t);
    emp_t *emp2 = XCALLOC(0, 1, emp_t);
    emp_t *emp3 = XCALLOC(0, 1, emp_t);
    emp_t *emp4 = XCALLOC(0, 1, emp_t);

    student_t *stud1 = XCALLOC(0, 1, student_t);
    student_t *stud2 = XCALLOC(0, 1, student_t);
    student_t *stud3 = XCALLOC(0, 1, student_t);

    //mm_print_memory_usage(0, "emp_t");
    xfree(emp1);
    xfree(emp2);
    xfree(emp3);
    emp1 = XCALLOC(0, 1, emp_t);
    emp2 = XCALLOC(0, 1, emp_t);
    emp3 = XCALLOC(0, 1, emp_t);
    xfree(emp4);
    emp4 = XCALLOC(0, 1, emp_t);
    xfree(stud1);
    xfree(stud2);
    xfree(stud3);
    xfree(emp1);
    xfree(emp2);
    xfree(emp3);
    xfree(emp4);
  
#if 0
    int i = 0;
    student_t *stud = NULL, *prev = NULL;
    student_t *first = NULL;
    for( ; i < 120; i++){
        stud = XCALLOC(0, 1, student_t);
        if(i == 0)
            first = stud;
        assert(stud);
        if(prev){
            prev->next = stud;
        }
        prev = stud;
    }
   // mm_print_memory_usage(0);
   // mm_print_block_usage();
    #endif
    #if 0
    i = 0;
    student_t *next = NULL;
    for( ; first; first = next){
        next = first->next;
        if(1 || i%4 == 0)
        xfree(first);
        i++;
    }
    #endif
    mm_print_memory_usage(0, "emp_t");
    mm_print_memory_usage(0, "student_t");
    mm_print_block_usage(0);
    return 0;
}
