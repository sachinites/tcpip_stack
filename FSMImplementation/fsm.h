/*
 * =====================================================================================
 *
 *       Filename:  fsm.h
 *
 *    Description:  This file contans the Data structure definitions for Generic FSM Project
 *
 *        Version:  1.0
 *        Created:  Saturday 31 August 2019 11:55:16  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the FSMProject distribution (https://github.com/sachinites).
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

#ifndef __FSM__
#define __FSM__

#include <assert.h>

typedef enum {

    FSM_FALSE,
    FSM_TRUE
} fsm_bool_t;

#define MAX_INP_BUFFER_LEN  128
#define MAX_OUP_BUFFER_LEN 128
#define MAX_TRANSITION_TABLE_SIZE   128
#define MAX_STATE_NAME_SIZE 32
#define MAX_FSM_NAME_SIZE 32
#define MAX_TRANSITION_KEY_SIZE 64
#define MAX_FSM_OUTPUT_BUFFER   1024
#define MAX_TT_ENTRY_CALLBACKS  5

typedef struct state_ state_t;
typedef struct fsm_ fsm_t;

typedef struct fsm_output_buff_{

    char output_buffer[MAX_FSM_OUTPUT_BUFFER];
    unsigned int curr_pos;
} fsm_output_buff_t;

typedef unsigned int (*input_fn)(    /*Returns the size of input buffer read*/
               char *,              /*Input Buffer*/
               unsigned int,        /*Size of Input Buffer*/ 
               unsigned int,        /*Starting position to read the buffer*/
               char *,              /*Data Read*/
               unsigned int *,      /*Size of Data Read*/
               unsigned int);       /*Max len of read out buffer*/

typedef void (*output_fn)(state_t *, state_t *,
                          char *, unsigned int,   /*Input buff, size of Inputputbuff*/
                          fsm_output_buff_t *);  /*Output Buff*/

void
fsm_echo_output_fn(state_t *from, state_t *to,
                   char *input_buff,
                   unsigned int input_buff_size,
                   fsm_output_buff_t *fsm_output_buff);

typedef fsm_bool_t (*input_matching_fn)(
    char *data1, 
    unsigned int size,
    char *data2,
    unsigned int user_data_len,
    unsigned int *length_read);

typedef struct tt_entry_ {

    char transition_key[MAX_TRANSITION_KEY_SIZE];
    unsigned int transition_key_size;
    output_fn outp_fn;
    state_t *next_state;
    input_matching_fn 
        input_matching_fn_cb[MAX_TT_ENTRY_CALLBACKS];
} tt_entry_t;

static inline fsm_bool_t 
is_tt_entry_empty (tt_entry_t *tt_entry){

    if(!tt_entry->next_state){
        return FSM_TRUE; 
    }

    return FSM_FALSE;
}

typedef struct tt_{

    tt_entry_t 
        tt_entry[MAX_TRANSITION_TABLE_SIZE];
} tt_t;


struct state_ {

    /*Name of the state, must be unique within FSM*/
    char state_name[MAX_STATE_NAME_SIZE];
    /*Transition Table of the state*/
    tt_t state_trans_table;
    /*Boolean if the state is final or not*/
    fsm_bool_t is_final; 
};

static inline tt_entry_t *get_tt_entry(
                    state_t *state, 
                    int index){

    assert(index < MAX_TRANSITION_TABLE_SIZE);
    return &(state->state_trans_table.tt_entry[index]);
}

void
init_fsm_output_buffer(fsm_output_buff_t *fsm_output_buff);

struct fsm_{

    /*Intitial state of FSM to start with*/
    state_t *initial_state;
    /*Name of FSM*/
    char fsm_name[MAX_FSM_NAME_SIZE];
    /* Application provided input data to parse
     * by FSM*/
    char input_buffer[MAX_INP_BUFFER_LEN];
    /* Length of above data*/
    unsigned int input_buffer_size;
    /*Cursor to read the above input_buffer in coninuation*/
    unsigned int input_buffer_cursor;
    /* If FSM need to produce some output, the output
     * data shall be stored in this buffer*/
    fsm_output_buff_t fsm_output_buff;
    /* A generic function to match the input string with the
     * key of transition table*/
    input_matching_fn input_matching_fn_cb;
};

void
fsm_register_input_matching_fn_cb(fsm_t *fsm,
        input_matching_fn input_matching_fn_cb);

void
set_fsm_initial_state(fsm_t *fsm, state_t *state);

void
set_fsm_input_buffer_size(fsm_t *fsm, unsigned int size);

void
set_fsm_default_input_fn(fsm_t *fsm, input_fn default_input_fn);

void
set_fsm_default_output_fn(fsm_t *fsm, output_fn default_output_fn);

state_t *
create_new_state(char *state_name, fsm_bool_t is_final); 

tt_entry_t * create_and_insert_new_tt_entry(tt_t *trans_table,
                                    char *transition_key,
                                    unsigned int sizeof_key,
                                    output_fn outp_fn,
                                    state_t *next_state);
void
create_and_insert_new_tt_entry_wild_card(state_t *from_state, 
                                         state_t *to_state, 
                                         output_fn output_fn_cb);

fsm_t *create_new_fsm(const char *fsm_name);

#define FSM_ITERATE_TRANS_TABLE_BEGIN(tr_table_ptr, tt_entry_ptr)   \
    do{ \
        unsigned int index = 0; \
        for(; index < MAX_TRANSITION_TABLE_SIZE; index++){  \
            tt_entry_ptr = &(tr_table_ptr->tt_entry[index]);   \
            if(is_tt_entry_empty(tt_entry_ptr) == FSM_TRUE)    \
                break;  \


#define FSM_ITERATE_TRANS_TABLE_END(tr_table_ptr, tt_entry_ptr) \
    }}while(0);

tt_entry_t *
get_next_empty_tt_entry(tt_t *trans_table);

void print_fsm(fsm_t *fsm);
void print_state(state_t *state);


typedef enum {

    FSM_NO_TRANSITION,
    FSM_NO_ERROR
} fsm_error_t;

fsm_error_t
execute_fsm(fsm_t *fsm, 
            char *input_buffer, 
            unsigned int size,
            fsm_output_buff_t *output_buffer,
            fsm_bool_t *fsm_result);

void
register_input_matching_tt_entry_cb(tt_entry_t *tt_entry, 
                            input_matching_fn input_matching_fn_cb);

#endif /* __FSM__ */
