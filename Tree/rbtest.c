/*
 * =====================================================================================
 *
 *       Filename:  rbtest.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  Wednesday 11 April 2018 09:21:30  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the XXX distribution (https://github.com/sachinites).
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

#include "redblack.h"
#include <stdio.h>

typedef struct complex_{

    int a;
    int b;
    rbnode node;
} complex_t;

#define offset(struct_name, fld_name) (unsigned int)&(((struct_name *)0)->fld_name)

RBNODE_TO_STRUCT(rbnode_to_complex_no, complex_t, node);

int
compare_complex_no(void *_c1, void *_c2){

    complex_t *c1,*c2;
    c1 = _c1;
    c2 = _c2;
    
    if((c1->a *c1->a + c1->b*c1->b) < 
            (c2->a *c2->a + c2->b*c2->b)){
        return -1;   
    }
    if((c1->a *c1->a + c1->b*c1->b) > 
            (c2->a *c2->a + c2->b*c2->b)){
        return 1;   
    }
    return 0;
}

int
complex_key_match(void *key, void *user_data){

    int a = (int)key;
    complex_t *c = user_data;
    if(c->a == a) return 0;
    return -1;
}


int
main(int argc, char **argv){

    rbroot crbroot;
    _redblack_root_init(&crbroot, FALSE, offset(complex_t, node), TRUE);
    register_rbtree_compare_fn(&crbroot, compare_complex_no);
    complex_t c1 ;
    _redblack_node_init(&crbroot, &c1.node);
    c1.a = 10;
    c1.b = 5;
    complex_t c2 ;
    _redblack_node_init(&crbroot, &c2.node);
    complex_t c3 ;
    _redblack_node_init(&crbroot, &c3.node);
    c2.a = 1;
    c2.b = 5;
    c3.a = 7;
    c3.b = 5;
    _redblack_add(&crbroot, &c1.node, 0);
    _redblack_add(&crbroot, &c2.node, 0);
    _redblack_add(&crbroot, &c3.node, 0);

    rbroot *first_node = _redblack_find_next(&crbroot, NULL);
    complex_t *first_c = rbnode_to_complex_no(first_node);
    printf("first_c : look up result = a,b = %d,%d\n", first_c->a, first_c->b);

    rbnode *curr = NULL;
    ITERATE_RB_TREE_BEGIN(&crbroot, curr){

        complex_t *c = rbnode_to_complex_no(curr);
        printf("a = %d, b = %d\n", c->a, c->b);
    } ITERATE_RB_TREE_END;

    curr = _redblack_lookup(&crbroot, 7, complex_key_match);
    complex_t *user_data = rbnode_to_complex_no(curr);

    printf("look up result = a,b = %d,%d\n", user_data->a, user_data->b);

    _redblack_flush(&crbroot);

    char c = _redblack_tree_empty(&crbroot);

    if(c){
        printf("Empty\n");
    }

    ITERATE_RB_TREE_BEGIN(&crbroot, curr){

        complex_t *c = rbnode_to_complex_no(curr);
        printf("a = %d, b = %d\n", c->a, c->b);
    } ITERATE_RB_TREE_END;

    return 0;
}
