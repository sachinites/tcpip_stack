/*
 * =====================================================================================
 *
 *       Filename:  string_util.c
 *
 *    Description:  String utilities
 *
 *        Version:  1.0
 *        Created:  Thursday 03 August 2017 05:35:37  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2017), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#include "string_util.h"
#include <stdlib.h>
#include <assert.h>
#include "cliconst.h"
#include <ctype.h>
#include <stdio.h>

static char a_str[CONS_INPUT_BUFFER_SIZE];
char temp[ LEAF_ID_SIZE + 2];

static char * tokens[MAX_CMD_TREE_DEPTH];

void
init_token_array(){

    int i = 0;
    for(; i < MAX_CMD_TREE_DEPTH; i++){
        tokens[i] = calloc(1, LEAF_VALUE_HOLDER_SIZE);
    }
}

void
re_init_tokens(int token_cnt){
    
    int i = 0;
    for(; i < token_cnt; i++){
        memset(tokens[i], 0, LEAF_VALUE_HOLDER_SIZE);
    }
}

void
tokenize(char *token, unsigned int size, unsigned int index){
    
    if(size > LEAF_VALUE_HOLDER_SIZE)
        assert(0);

    strncpy(tokens[index], token, size);
}

void
untokenize(unsigned int index){

    memset(tokens[index], 0, LEAF_VALUE_HOLDER_SIZE);
}

char *
get_token(unsigned int index){

    return tokens[index];
}

char** tokenizer(char* _a_str, const char a_delim, size_t *token_cnt){
   
    char *token = NULL;
    int i = 0;
    char delim[2];
    memset(a_str, 0, CONS_INPUT_BUFFER_SIZE);
    strncpy(a_str, _a_str, strlen(_a_str));
    a_str[strlen(_a_str)] = '\0';

    string_space_trim(a_str);

    if(strlen(a_str) < 1){
        *token_cnt = 0;
        return NULL;
    }

    delim[0] = a_delim;
    delim[1] = '\0';

    token = strtok(a_str, delim);
    if(token){
        untokenize(i);
        strncpy(tokens[i], token, strlen(token));
        i++;
    }
    else{
        *token_cnt = 0;
        return NULL;
    }
    
    /* walk through other tokens */
    while( token != NULL ) 
    {
        token = strtok(NULL, delim);
        if(token){
            untokenize(i);
            strncpy(tokens[i], token, strlen(token));
            i++;
            if(i == MAX_CMD_TREE_DEPTH + 1){
                //printf("Warning : Max token limit (= %d) support exceeded\n", MAX_CMD_TREE_DEPTH);
                re_init_tokens(MAX_CMD_TREE_DEPTH);
                *token_cnt = 0;
                return &tokens[0];
            }
        }
    } 
    *token_cnt = i;
    return &tokens[0];
}

void
string_space_trim(char *string){

    if(!string)
        return;

    char* ptr = string;
    int len = strlen(ptr);

    if(!len){
        return;
    }

    if(!isspace(ptr[0]) && !isspace(ptr[len-1])){
        return;
    }

    while(len-1 > 0 && isspace(ptr[len-1])){
        ptr[--len] = 0;
    }

    while(*ptr && isspace(*ptr)){
        ++ptr, --len;
    }

    memmove(string, ptr, len + 1);
}


void
print_tokens(unsigned int index){
    
    unsigned int i = 0;
    for ( ; i < index; i++)
    {
        if(tokens[i] == NULL)
            break;

        printf("%s ", tokens[i]);
    }
}
