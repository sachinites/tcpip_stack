/*
 * =====================================================================================
 *
 *       Filename:  fsm.c
 *
 *    Description:  This file contans the implementation of core functions of Generic FSM Project
 *
 *        Version:  1.0
 *        Created:  Saturday 31 August 2019 12:10:59  IST
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "fsm.h"

extern fsm_bool_t
match_any_character_match_fn(char *data1, unsigned int size,
        char *data2, unsigned int user_data_len,
        unsigned int *length_read);

static fsm_bool_t
fsm_default_input_matching_fn(char *transition_key,
        unsigned int size,
        char *user_data,
        unsigned int user_data_len,
        unsigned int *length_read){

    if(size <= user_data_len){
        if(memcmp(transition_key, user_data, size))
            return FSM_FALSE;
        *length_read = size;
        return FSM_TRUE;
    }
    *length_read = 0;
    return FSM_FALSE;
}

void
fsm_echo_output_fn(state_t *from, state_t *to,
                   char *input_buff,
                   unsigned int input_buff_size,
                   fsm_output_buff_t *fsm_output_buff){

    memcpy(fsm_output_buff->output_buffer + fsm_output_buff->curr_pos, 
                input_buff, input_buff_size);
    fsm_output_buff->curr_pos += input_buff_size;
}


fsm_t *create_new_fsm(const char *fsm_name){

    fsm_t * fsm = calloc(1, sizeof(fsm_t));
    strncpy(fsm->fsm_name, fsm_name, MAX_FSM_NAME_SIZE - 1);
    fsm->fsm_name[MAX_FSM_NAME_SIZE - 1] = '\0';
    fsm_register_input_matching_fn_cb(fsm, 
        fsm_default_input_matching_fn);
    return fsm;
}

void
set_fsm_initial_state(fsm_t *fsm, state_t *state){
    
    assert(!fsm->initial_state);
    fsm->initial_state = state;
}

void
set_fsm_input_buffer_size(fsm_t *fsm, unsigned int size){

    fsm->input_buffer[size] = '\0';
    fsm->input_buffer_size = size;
}


state_t *
create_new_state(char *state_name,
                 fsm_bool_t is_final){

    assert(state_name);
    
    state_t *state = calloc(1, sizeof(state_t));
    
    strncpy(state->state_name, state_name, MAX_STATE_NAME_SIZE -1);
    state->state_name[MAX_STATE_NAME_SIZE -1] = '\0';

    state->is_final = is_final;
    return state;
}

tt_entry_t *
get_next_empty_tt_entry(tt_t *trans_table){

    tt_entry_t *tt_entry_ptr = NULL;
    
    assert(trans_table);

    FSM_ITERATE_TRANS_TABLE_BEGIN(trans_table, tt_entry_ptr){
        /*No Op*/
    } FSM_ITERATE_TRANS_TABLE_END(trans_table, tt_entry_ptr);

    if(is_tt_entry_empty(tt_entry_ptr) == FSM_TRUE)
        return tt_entry_ptr;

    return NULL;
}


tt_entry_t *
create_and_insert_new_tt_entry(tt_t *trans_table,
        char *transition_key,
        unsigned int sizeof_key,
        output_fn outp_fn,
        state_t *next_state){

    assert(sizeof_key < MAX_TRANSITION_KEY_SIZE);

    tt_entry_t *tt_entry_ptr = get_next_empty_tt_entry(trans_table);
    
    if(!tt_entry_ptr){
        printf("FATAL : Transition Table is Full\n");
        return NULL;
    }

    memcpy(tt_entry_ptr->transition_key, transition_key, sizeof_key);
    tt_entry_ptr->transition_key[sizeof_key] = '\0';
    tt_entry_ptr->transition_key_size = sizeof_key;
    tt_entry_ptr->outp_fn = outp_fn;
    tt_entry_ptr->next_state = next_state;
    return tt_entry_ptr;
}

/* A transition Table Entry which tskes the transition from 
 * 'from_state' to 'to_state,' irrespective of the input
 * character, it may produce output*/
void
create_and_insert_new_tt_entry_wild_card(state_t *from_state, 
                                     state_t *to_state, 
                                     output_fn output_fn_cb){

    tt_entry_t *tt_entry = create_and_insert_new_tt_entry(&from_state->state_trans_table,
                                   0, 0, output_fn_cb, to_state);
    register_input_matching_tt_entry_cb(tt_entry, match_any_character_match_fn);
}


static fsm_bool_t
fsm_evaluate_transition_entry_match(fsm_t *fsm, 
                                    tt_entry_t *tt_entry, 
                                    char *input_buffer,
                                    unsigned int input_buffer_len,
                                    unsigned int *length_read) {

   unsigned int i = 0;
   fsm_bool_t is_tt_entry_cb_present = FSM_FALSE;
   fsm_bool_t res = FSM_FALSE;
      
   if(!input_buffer)
       return FSM_TRUE;

   is_tt_entry_cb_present = tt_entry->input_matching_fn_cb[0] ? \
                            FSM_TRUE : FSM_FALSE;

   if(is_tt_entry_cb_present){

        for(; i < MAX_TT_ENTRY_CALLBACKS; i++){

            if(!tt_entry->input_matching_fn_cb[i]){
                return FSM_FALSE;
            }

            if((tt_entry->input_matching_fn_cb[i])(
                    NULL, 0, input_buffer, input_buffer_len, length_read)){
                return FSM_TRUE;
            }
            /*Be immune !*/
            *length_read = 0;
        }
        return FSM_FALSE;
   }

   res = fsm->input_matching_fn_cb(tt_entry->transition_key,
           tt_entry->transition_key_size,
           input_buffer, input_buffer_len, length_read);

    if(res == FSM_TRUE){
        *length_read = tt_entry->transition_key_size;
    }

   return res;
}

static state_t *
fsm_apply_transition(fsm_t *fsm, state_t *state, 
                     char *input_buffer,        /*Input buffer to parse*/
                     unsigned int size,         /*Remaining length of the buffer*/
                     unsigned int *length_read, /* initialized to zero, returns the no of bytes read*/
                     fsm_output_buff_t *output_buffer){


   tt_entry_t *tt_entry = NULL;
   state_t *next_state = NULL;

   assert(size);

   FSM_ITERATE_TRANS_TABLE_BEGIN((&state->state_trans_table),
                                 tt_entry){

        if((tt_entry->transition_key_size <= size) &&
            fsm_evaluate_transition_entry_match(fsm, 
                                                tt_entry, 
                                                input_buffer,
                                                size,
                                                length_read)){
            
            next_state = tt_entry->next_state;
             
            if(tt_entry->outp_fn){
                tt_entry->outp_fn(state, next_state, 
                            input_buffer, 
                            tt_entry->transition_key_size,
                            output_buffer);
            }

            return next_state;
        }

   }FSM_ITERATE_TRANS_TABLE_END(&state->state_trans_table,
                                 tt_entry);
   return NULL;
}


fsm_error_t
execute_fsm(fsm_t *fsm, 
            char *input_buffer,         /*Input buffer containing user data*/
            unsigned int size,          /*Size of the data in the buffer*/
            fsm_output_buff_t *output_buffer,   /*output buffer to write data into*/
            fsm_bool_t *fsm_result){            /*A flag to track if data parsing ends in final state or not */


   state_t *initial_state = fsm->initial_state;
   assert(initial_state);

   state_t *current_state = initial_state;
   state_t *next_state = NULL;

   fsm->input_buffer_cursor = 0;
   unsigned int length_read = 0;
   unsigned int input_buffer_len = 0;
   char *buffer_to_parse;

   if(fsm_result){
       *fsm_result = FSM_FALSE;
   }

   /*Use Application Supplied Buffer*/
   if(input_buffer && size){
        buffer_to_parse = input_buffer;
        input_buffer_len = size;
   }
   else{
        /*Use FSM buffer set by the application*/
        buffer_to_parse = fsm->input_buffer;
        input_buffer_len = fsm->input_buffer_size;
   }

   /*If application has not supplied output buffer,
    * Use FSM's internal output buffer*/
   if(!output_buffer){
        output_buffer = &fsm->fsm_output_buff;
   }
   
   init_fsm_output_buffer(output_buffer);
   
   while(fsm->input_buffer_cursor < MAX_INP_BUFFER_LEN){
   
        length_read = 0;
         
        next_state = fsm_apply_transition(fsm, current_state, 
                        buffer_to_parse + fsm->input_buffer_cursor, 
                        (input_buffer_len - fsm->input_buffer_cursor),
                        &length_read, output_buffer);
        
        if(!next_state){
            return FSM_NO_TRANSITION;
        }

        if(length_read){

            fsm->input_buffer_cursor += length_read;
            current_state = next_state;

            if(fsm->input_buffer_cursor == input_buffer_len)
                break;

            continue;
        }
        break;
   }
 
   if(fsm_result){ 
       *fsm_result = current_state->is_final; 
   }

#if 0
   if(output_buffer->curr_pos < MAX_FSM_OUTPUT_BUFFER)
       output_buffer->output_buffer[output_buffer->curr_pos] = '\0';
#endif

   return FSM_NO_ERROR;
}

void
fsm_register_input_matching_fn_cb(fsm_t *fsm, 
        input_matching_fn input_matching_fn_cb){
    
    fsm->input_matching_fn_cb = input_matching_fn_cb;
}

void
init_fsm_output_buffer(fsm_output_buff_t *fsm_output_buff){
    
    memset(fsm_output_buff->output_buffer, 0, MAX_OUP_BUFFER_LEN);
    fsm_output_buff->curr_pos = 0;
}

void
register_input_matching_tt_entry_cb(tt_entry_t *tt_entry,
                            input_matching_fn input_matching_fn_cb){
    
    unsigned int i = 0;
    for(; i < MAX_TT_ENTRY_CALLBACKS; i++){
        if(tt_entry->input_matching_fn_cb[i])
            continue;
        tt_entry->input_matching_fn_cb[i] = 
            input_matching_fn_cb;
            return;   
    }
    assert(0);
}
