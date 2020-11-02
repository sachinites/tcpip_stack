/*
 * =====================================================================================
 *
 *       Filename:  glthread.h
 *
 *    Description:  This file defines the Data structure and APIs for Glue thread
 *
 *        Version:  1.0
 *        Created:  Monday 12 March 2018 02:01:51  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the SPFComputation distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#ifndef __GLUETHREAD__
#define __GLUETHREAD__

typedef struct _glthread{

    struct _glthread *left;
    struct _glthread *right;
} glthread_t;

void
glthread_add_next(glthread_t *base_glthread, glthread_t *new_glthread);

void
glthread_add_before(glthread_t *base_glthread, glthread_t *new_glthread);

void
remove_glthread(glthread_t *glthread);

void
init_glthread(glthread_t *glthread);

void
glthread_add_last(glthread_t *base_glthread, glthread_t *new_glthread);

#define IS_QUEUED_UP_IN_THREAD(glthreadptr) \
	(!((glthreadptr)->right == 0 && (glthreadptr)->left == 0))

#define IS_GLTHREAD_LIST_EMPTY(glthreadptr)         \
    ((glthreadptr)->right == 0 && (glthreadptr)->left == 0)

#define GLTHREAD_TO_STRUCT(fn_name, structure_name, field_name)                        \
    static inline structure_name * fn_name(glthread_t *glthreadptr){                   \
        return (structure_name *)((char *)(glthreadptr) - (char *)&(((structure_name *)0)->field_name)); \
    }

/* delete safe loop*/
/*Normal continue and break can be used with this loop macro*/

#define BASE(glthreadptr)   ((glthreadptr)->right)

#define ITERATE_GLTHREAD_BEGIN(glthreadptrstart, glthreadptr)                                      \
{                                                                                                  \
    glthread_t *_glthread_ptr = NULL;                                                              \
    glthreadptr = BASE(glthreadptrstart);                                                          \
    for(; glthreadptr!= NULL; glthreadptr = _glthread_ptr){                                        \
        _glthread_ptr = (glthreadptr)->right;

#define ITERATE_GLTHREAD_END(glthreadptrstart, glthreadptr)                                        \
        }}

#define GLTHREAD_GET_USER_DATA_FROM_OFFSET(glthreadptr, offset)  \
    (void *)((char *)(glthreadptr) - offset)

void
delete_glthread_list(glthread_t *base_glthread);

unsigned int 
get_glthread_list_count(glthread_t *base_glthread);

void
glthread_priority_insert(glthread_t *base_glthread,     
                         glthread_t *glthread,
                         int (*comp_fn)(void *, void *),
                         int offset);

glthread_t *
dequeue_glthread_first(glthread_t *base_glthread);

#if 0
void *
gl_thread_search(glthread_t *base_glthread,
        void *(*thread_to_struct_fn)(glthread_t *),
        void *key,
        int (*comparison_fn)(void *, void *));

#endif
#endif /* __GLUETHREAD__ */
