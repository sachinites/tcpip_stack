/*
 * =====================================================================================
 *
 *       Filename:  app.c
 *
 *    Description:  This file is a test demo for making use of fsm project
 *
 *        Version:  1.0
 *        Created:  Saturday 31 August 2019 02:14:25  IST
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
#include <stdbool.h>
#include "fsm.h"
#include "std_fsm.h"

void 
bit_flipper_output_fn_gen(state_t *from, state_t *to,
                          char *input_buff, 
                          unsigned int input_buff_size,
                          fsm_output_buff_t *fsm_output_buff){

    char out;
    out = (*input_buff == '1') ? '0' : '1';
    fsm_output_buff->curr_pos += snprintf(fsm_output_buff->output_buffer + 
                                          fsm_output_buff->curr_pos, 
             (MAX_FSM_OUTPUT_BUFFER - fsm_output_buff->curr_pos - 1), 
             "%s-->%c|%c-->%s\n", 
             from->state_name, *input_buff, out, 
             to->state_name);
}

int
main(int argc, char **argv){

  /*Create a FSM*/
  fsm_t *fsm = create_new_fsm("Bit Flipper");
  
  /*Create FSM State*/
  state_t *state_S0 = create_new_state("S0", FSM_TRUE);
  //state_t *state_S0 = create_new_state(fsm, "S0", FSM_TRUE, bit_flipper_key_match_fn);

  /*Set FSM initial state*/
  set_fsm_initial_state(fsm, state_S0);

  /*Insert Transitions into State's Transition Table*/
  char bit = '0';
  create_and_insert_new_tt_entry(&state_S0->state_trans_table,
                                 &bit, 1,
                                 bit_flipper_output_fn_gen,
                                 state_S0);

  bit = '1';
  create_and_insert_new_tt_entry(&state_S0->state_trans_table,
                                 &bit, 1, 
                                 bit_flipper_output_fn_gen,
                                 state_S0);



  /*
   * FSM creation has been complete, not let us see how our FSM perform
   * */
  fsm_bool_t fsm_result; 
  fsm_error_t fsm_error;
  
  fsm_error = execute_fsm(fsm, 
                          "0000000\0",         /*Input String to process*/
                          strlen("0000000\0"), /*Length of the Input String*/
                          0,                   /*We want the output in the FSM Output buffer instead of application specific buffer*/
                          &fsm_result);        /*Did the FSM execution ended in Final State*/

  if(fsm_error == FSM_NO_ERROR){
        printf("FSM result = %s\n", fsm_result == FSM_TRUE ? "FSM_TRUE":"FSM_FALSE");
        printf("FSM Output string : \n%s\n", fsm->fsm_output_buff.output_buffer);
  }
    
  /*Now, Application wants the FSM output in
   * its own buffer*/ 
  fsm_output_buff_t fsm_output_buff;
  init_fsm_output_buffer(&fsm_output_buff);
  
  fsm_error = execute_fsm(fsm, 
                          "1111111\0",         /*Input String to process*/
                          strlen("1111111\0"), /*Length of the Input String*/
                          &fsm_output_buff,    /*We want the output in the application specific buffer instead of FSM internal output buffer*/
                          &fsm_result);        /*Did the FSM execution ended in Final State*/
                                 
  if(fsm_error == FSM_NO_ERROR){
        printf("FSM result = %s\n", fsm_result == FSM_TRUE ? "FSM_TRUE":"FSM_FALSE");
        printf("FSM Output string : \n%s\n", fsm_output_buff.output_buffer);
  }

  /*Assign the input buffer to FSM to execute*/
  strncpy((char *)fsm->input_buffer, "0101010101010\0", strlen("0101010101010"));
  set_fsm_input_buffer_size(fsm, strlen("0101010101010\0"));
  fsm_error = execute_fsm(fsm, 
                          0,        /*We want to use FSM to use its internal Input Buffer which we have initialized above*/
                          0,        /*Length of the Input String*/
                          &fsm_output_buff,    /*We want the output in the application specific buffer instead of FSM internal output buffer*/
                          &fsm_result);        /*Did the FSM execution ended in Final State*/
                                 
  if(fsm_error == FSM_NO_ERROR){
        printf("FSM result = %s\n", fsm_result == FSM_TRUE ? "FSM_TRUE":"FSM_FALSE");
        printf("FSM Output string : \n%s\n", fsm_output_buff.output_buffer);
  }

  /*FSM For email Validation*/
  fsm_t *email_validator = email_validator_fsm();
  fsm_error = execute_fsm(email_validator, 
                          "sachinites@gmail.com\0",
                          strlen("sachinites@gmail.com\0"),
                          0,
                          &fsm_result);

  if(fsm_error == FSM_NO_ERROR) {
      if(fsm_result == FSM_TRUE)
          printf("Valid email\n");
      else
          printf("InValid Email\n");
  }
  else{
      printf("FSM State Machine Failed\n");
  }


/*Demonstration of SubString Counter*/

  fsm_t *fsm_substr_counter = fsm_substring_counter("Abhi\0", strlen("Abhi\0"));
  //fsm_register_input_matching_fn_cb(fsm_substr_counter, match_any_character_match_fn);
  char *input_string = 
    "Hello, My name is Abhi. "
    "Visit my website : https://www.csepracticals.com "
    "which was created by Abhishek Sagar\0";

  fsm_error = execute_fsm(fsm_substr_counter,
                           input_string,
                           strlen(input_string),
                           0,
                           0);

  if(fsm_error == FSM_NO_ERROR){
    
    char str[5];
    unsigned int i = 0;

    for( ; i < fsm_substr_counter->fsm_output_buff.curr_pos; i++){
        memset(str, 0, 5);
        strncpy((char *)str, (char *)(*(((unsigned int *)(fsm_substr_counter->fsm_output_buff.output_buffer)) + i)), 4);
        str[4] = '\0';
        printf("%s\n", str);
    }
  }

  fsm_t *fsm_bin_to_hex = fsm_binary_to_hex();
  fsm_error = execute_fsm(fsm_bin_to_hex,
                          "00011111111111111111111111111111\0",
                   strlen("00011111111111111111111111111111\0"),
                          0, 0);


  if(fsm_error == FSM_NO_ERROR){
        printf("Hex = %s\n", fsm_bin_to_hex->fsm_output_buff.output_buffer);
  }                                                
  return 0;
}
