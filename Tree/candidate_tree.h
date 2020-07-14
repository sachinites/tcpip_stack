/*
 * =====================================================================================
 *
 *       Filename:  candidate_tree.h
 *
 *    Description:  Candidatre tree built on top of redblack Tree Library
 *
 *        Version:  1.0
 *        Created:  Monday 21 May 2018 10:33:50  IST
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

#ifndef __CANDIDATE_TREE__
#define __CANDIDATE_TREE__

#include "redblack.h"
#include <assert.h>

typedef struct rbroot_ candidate_tree_t;

#define CANDIDATE_TREE_INIT(ctreeptr, _offset, is_dup)       \
    (_redblack_root_init(ctreeptr, 0, _offset, is_dup))

#define CANDIDATE_TREE_REG_COMPARE_CB(ctreeptr, cb)  \
    register_rbtree_compare_fn(ctreeptr, cb)

#define RE_INIT_CANDIDATE_TREE(ctreeptr)    \
    (_redblack_flush(ctreeptr))

#define IS_CANDIDATE_TREE_EMPTY(ctreeptr)   \
    (_redblack_tree_empty(ctreeptr))

#define INSERT_NODE_INTO_CANDIDATE_TREE(ctreeptr, rbnodeptr)    \
    _redblack_node_init(ctreeptr, rbnodeptr);                   \
    (_redblack_add(ctreeptr, rbnodeptr, 0))

#define GET_CANDIDATE_TREE_TOP(ctreeptr)    \
        (_redblack_find_next(ctreeptr, NULL))

#define GET_CANDIDATE_TREE_FIRST(ctreeptr)  \
    (GET_CANDIDATE_TREE_TOP(ctreeptr, NULL))

#define CANDIDATE_TREE_NODE_INIT(ctreeptr, rbnodeptr) \
    (_redblack_node_init(ctreeptr, rbnodeptr))

static inline void
REMOVE_CANDIDATE_TREE_TOP(candidate_tree_t *ctreeptr){

    rbnode *_rbnode = _redblack_find_next(ctreeptr, NULL);
    if(!_rbnode)
        return;
    _redblack_delete(ctreeptr, _rbnode);
}

static inline rbnode *
GET_CANDIDATE_TREE_NEXT_NODE(candidate_tree_t *ctreeptr, 
                        rbnode *_rbnode){

    return _redblack_find_next(ctreeptr, _rbnode); 
}

static inline rbnode *
CANDIDATE_TREE_REMOVE_NODE(candidate_tree_t *ctreeptr,
                        rbnode *_rbnode){
    
    _redblack_delete(ctreeptr, _rbnode);
}

#define REMOVE_CANDIDATE_TREE_FIRST(ctreeptr)   \
    REMOVE_CANDIDATE_TREE_TOP(ctreeptr) 

#define FREE_CANDIDATE_TREE_INTERNALS(ctreeptr) \
    _redblack_flush(ctreeptr);                  \
    _redblack_root_delete(ctreeptr)

#define CANDIDATE_TREE_NODE_REFRESH(ctreeptr, rbnodeptr)    \
    _redblack_delete(ctreeptr, rbnodeptr);                  \
    INSERT_NODE_INTO_CANDIDATE_TREE(ctreeptr, rbnodeptr)

#endif /* __CANDIDATE_TREE__ */
