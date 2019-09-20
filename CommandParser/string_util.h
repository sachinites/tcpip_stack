/*
 * =====================================================================================
 *
 *       Filename:  string_util.h
 *
 *    Description:  iString util
 *
 *        Version:  1.0
 *        Created:  Thursday 03 August 2017 05:37:07  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#ifndef __STRING_UTIL__
#define __STRING_UTIL__
#include <string.h>


char** tokenizer(char* a_str, 
                 const char a_delim, 
                 size_t *token_cnt);

void
string_space_trim(char *string);

void
print_tokens(unsigned int index);

void
init_token_array();

void
re_init_tokens(int token_cnt);

void
tokenize(char *token, unsigned int size, unsigned int index);

void
untokenize(unsigned int index);

char *
get_token(unsigned int index);

#endif
