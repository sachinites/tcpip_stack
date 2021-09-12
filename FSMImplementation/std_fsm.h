/*
 * =====================================================================================
 *
 *       Filename:  std_fsm.h
 *
 *    Description:  This file contains standard Finite state machines and Common Reader Functions Declarations
 *
 *        Version:  1.0
 *        Created:  Saturday 31 August 2019 09:03:35  IST
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

#ifndef __STD_FSM__
#define __STD_FSM__

#include "fsm.h"

/* Standard utility callbacks for transition table
 * entry matching*/

fsm_bool_t
match_any_0_9_match_fn(char *data1,         /*Transition entry key, which will be empty buffer*/
        unsigned int size,                  /*size shall be zero*/
        char *data2,                        /*Data from User Input*/
        unsigned int user_data_len,
        unsigned int *length_read);

fsm_bool_t
match_any_a_z_match_fn(char *data1,       /*Transition entry key, which will be empty buffer*/
        unsigned int size,                /*size shall be zero*/
        char *data2,                      /*Data from User Input*/
        unsigned int user_data_len,
        unsigned int *length_read);

fsm_bool_t
match_any_A_Z_match_fn(char *data1,       /*Transition entry key, which will be empty buffer*/
        unsigned int size,                /*size shall be zero*/
        char *data2,                      /*Data from User Input*/
        unsigned int user_data_len,
        unsigned int *length_read);

fsm_bool_t
match_any_0_9_or_a_z_or_A_Z_match_fn(char *data1, 
                                     unsigned int size,
                                     char *data2,
                                     unsigned int user_data_len,
                                     unsigned int *length_read);

fsm_bool_t
match_any_character_match_fn(char *data1, unsigned int size,
                             char *data2, unsigned int user_data_len,
                             unsigned int *length_read);


/*Standard output functions*/
void
convert_binary_to_hex(state_t *from, state_t *to,
                       char *input_buff,
                       unsigned int input_buff_size,
                       fsm_output_buff_t *fsm_output_buff);



/*Standard Example FSMs*/
fsm_t *email_validator_fsm();
fsm_t *phone_number_validator_fsm();

/*https://www.geeksforgeeks.org/mealy-and-moore-machines*/
fsm_t *mealy_machine_fsm();
fsm_t *moore_machine_fsm();

fsm_t *fsm_substring_counter(char *common_trans_key, 
                              unsigned int trans_key_size);

fsm_t *
fsm_binary_to_hex();

bool
ip_validate(char *ip_addr_copy);

#endif /* __STD_FSM__ */
