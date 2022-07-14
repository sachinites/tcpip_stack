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


#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include "string_util.h"
#include "cliconst.h"

static char a_str[CONS_INPUT_BUFFER_SIZE];
char temp[ LEAF_ID_SIZE + 2];

static char * tokens[MAX_CMD_TREE_DEPTH];

void
init_token_array(){

    int i = 0;
    for(; i < MAX_CMD_TREE_DEPTH; i++){
        tokens[i] = (char *)calloc(1, LEAF_VALUE_HOLDER_SIZE);
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

void replaceSubstring(char string[], char sub[], char new_str[])
{
    int stringLen, subLen, newLen;
    int i = 0, j, k;
    int flag = 0, start, end;
    stringLen = strlen(string);
    subLen = strlen(sub);
    newLen = strlen(new_str);

    for (i = 0; i < stringLen; i++)
    {
        flag = 0;
        start = i;
        for (j = 0; string[i] == sub[j]; j++, i++)
            if (j == subLen - 1)
                flag = 1;
        end = i;
        if (flag == 0)
            i -= j;
        else
        {
            for (j = start; j < end; j++)
            {
                for (k = start; k < stringLen; k++)
                    string[k] = string[k + 1];
                stringLen--;
                i--;
            }

            for (j = start; j < start + newLen; j++)
            {
                for (k = stringLen; k >= j; k--)
                    string[k + 1] = string[k];
                string[j] = new_str[j - start];
                stringLen++;
                i++;
            }
        }
    }
}


bool
pattern_match(char string[], int string_size, char pattern[]) {

    if (string_size == 0) {
        return false;
    }
    return (strstr(string, pattern));
}

int
grep (char string[], int string_size, char pattern[]) {

    int rc = 0;
    char *token;

    if (!string_size) return 0;
    
    char *temp_buff = (char *)calloc(1, string_size);
    
    memcpy(temp_buff, string, string_size);
    memset (string, 0, string_size);

    token = strtok(temp_buff, "\n");

    while (token) {

        if (pattern_match(token, strlen(token), pattern)) {

            rc += sprintf(string + rc, "%s\n", token);
        }
        token = strtok(NULL, "\n");
    }
    free(temp_buff);
    return rc;
}

static bool
is_number (char *string) {

    int i = 0;
    while (string[i] != '\0') {

        if (string[i] == '0' || 
             string[i] == '1' ||
             string[i] == '2' ||
             string[i] == '3' ||
             string[i] == '4' ||
             string[i] == '5' ||
             string[i] == '6' ||
             string[i] == '7' ||
             string[i] == '8' ||
             string[i] == '9' ) {

                i++;
                continue;
             }
             else {
                 return false;
             }
    }
    return true;
}


uint64_t
string_fetch_integer(char *string, int string_size, int index) {

    int count = 0;
    char *token;

    if (!string_size) return 0;

    char *temp_buff = (char *)calloc(1, string_size);
    memcpy(temp_buff, string, string_size);
    
    token = strtok(temp_buff, " ");

    while (token) {

        if (!is_number(token)) {
            token = strtok(NULL, " ");
            continue;
        }

        count++;
        if (index == count) {
            free(temp_buff);
            return atoi(token);
        }
        
        token = strtok(NULL, " ");
    }
    free(temp_buff);
    return 0;
}

#if 0
int 
main(int argc, char **argv) {

    char *sample1 = "LSP : 122.1.1.0          Seq # : 14      size(B) : 95      ref_c : 1     Life Time Remaining : 2372 sec\0";
    uint64_t int1 = string_fetch_integer(sample1, strlen(sample1), 1);
    printf("%d %u\n", __LINE__, int1);
    int1 = string_fetch_integer(sample1, strlen(sample1), 2);
    printf("%d %u\n", __LINE__, int1);
    int1 = string_fetch_integer(sample1, strlen(sample1), 3);
    printf("%d %u\n", __LINE__, int1);
     int1 = string_fetch_integer(sample1, strlen(sample1), 4);
    printf("%d %u\n", __LINE__, int1);
    return 0;
}
#endif
