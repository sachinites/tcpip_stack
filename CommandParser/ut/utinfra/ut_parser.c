#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <mqueue.h>
#include <errno.h>
#include <semaphore.h>
#include "../../gluethread/glthread.h"
#include "../../css.h"
#include "../../libcli.h"
#include "../../cmdtlv.h"
#include "../../string_util.h"

#define UT_PARSER_BUFF_MAX_SIZE 2048

/* Global variables for UT parser */
static int UT_PARSER_MSG_Q_FD; 
static bool TC_RUNNING = false;
static char ut_parser_recv_buff[UT_PARSER_BUFF_MAX_SIZE];
static int ut_parser_recv_buff_data_size;
static bool ut_parser_debug = false;
static FILE *ut_log_file = NULL;
static uint64_t int_store1, int_store2, int_store3;
static struct timespec mq_wait_time;

#define MAX_MESSAGES    1
#define MAX_MSG_SIZE       2048
#define QUEUE_PERMISSIONS   0660

extern CMD_PARSE_STATUS
parse_input_cmd(char *input, unsigned int len, bool *is_repeat_cmd);

void
ut_parser_init ( ) {

    struct mq_attr attr;

    ut_log_file = fopen("CommandParser/ut/utinfra/ut_log_file.txt", "w");
    assert(ut_log_file);

    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;

    if ((UT_PARSER_MSG_Q_FD = mq_open("/ut_parser_msg_q",
                                      O_RDWR | O_CREAT,
                                      QUEUE_PERMISSIONS, &attr)) == -1) {

        printf("UT Parser mq_open failed, errno = %d\n", errno);
        exit(1);
    }

    mq_wait_time.tv_sec = 3;
    mq_wait_time.tv_nsec = 0;
}

typedef struct tc_result_ {

    uint16_t step_no;
    bool pass;
    bool pattern_match;
    glthread_t glue;
} tc_result_t;
GLTHREAD_TO_STRUCT(glue_to_tc_result, tc_result_t, glue);

static void
tc_append_result(glthread_t *head, uint16_t step_no, bool pass, bool match) {

    tc_result_t *res = (tc_result_t *)calloc(1, sizeof(tc_result_t));
    res->step_no = step_no;
    res->pass = pass;
    res->pattern_match = match;
    init_glthread(&res->glue);
    glthread_add_last(head, &res->glue);
}

static void
tc_print_result (glthread_t *head) {

    int rc = 0;
    glthread_t *curr;
    tc_result_t *res;
    char buff[128];
    int pass_cnt = 0, fail_cnt = 0, total_cnt = 0;

    rc = sprintf(buff, "\n****  Result ******\n");
    printf("%s", buff);
    fwrite(buff, 1, rc, ut_log_file);

    ITERATE_GLTHREAD_BEGIN(head, curr) {

        res = glue_to_tc_result(curr);
        rc = sprintf(buff, "%s  STEP: %d : %s\n", 
            res->pattern_match ? "PATTERN-MATCH" : "PATTERN-NOT-PRESENT",
            res->step_no, res->pass ? "PASS" : "FAIL");
        printf("%s", buff);
        fwrite(buff, 1, rc, ut_log_file);
        res->pass ? pass_cnt++ : fail_cnt++;
        total_cnt++;
    } ITERATE_GLTHREAD_END(head, curr);

    printf ("Total TC : %d   Pass : %d   Fail %d\n", total_cnt, pass_cnt, fail_cnt);
    rc = sprintf(buff, "Total TC : %d   Pass : %d   Fail %d\n", 
                total_cnt, pass_cnt, fail_cnt);
    fwrite(buff, 1, rc, ut_log_file);
    fflush(ut_log_file);
}

static void
tc_cleanup_result_list(glthread_t *result_head) {

    glthread_t *curr;
    tc_result_t *res;

    ITERATE_GLTHREAD_BEGIN(result_head, curr) {

        remove_glthread(curr);
        res = glue_to_tc_result(curr);
        free(res);
    }
    ITERATE_GLTHREAD_END(result_head, curr);
}

bool
run_test_case(char *file_name, uint16_t tc_no) {

    int rc = 0;
    char *token;
    char buff[128];
    char *fget_ptr;
    bool tc_found = false;
    glthread_t result_head;
    uint16_t current_tc_no;
    char line[512];
    uint16_t current_step_no;
    bool is_repeat_cmd = false;
    CMD_PARSE_STATUS status = UNKNOWN;

     fget_ptr = NULL;
    init_glthread(&result_head);

    FILE *fp = fopen (file_name, "r");
    assert(fp);

    while (( fget_ptr = (fgets (line, sizeof(line), fp)))) {

            if (strlen(line) == 1 && line[0] == '\n') {
                printf("\n");
                rc = sprintf (buff, "\n");
                fwrite(buff, 1, rc, ut_log_file);
                fflush(ut_log_file);
            }

            if (line[0] != ':') continue;
            strtok(line, "\n");

            rc = sprintf(buff, "%lu", int_store1);
            replaceSubstring(line, "$INT_STORE1", buff);
            rc = sprintf(buff, "%lu", int_store2);
            replaceSubstring(line, "$INT_STORE2", buff);
            rc = sprintf(buff, "%lu", int_store3);
            replaceSubstring(line, "$INT_STORE3", buff);

            if (strncmp (line, ":TESTCASE-BEGIN:", strlen(":TESTCASE-BEGIN:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                current_tc_no = atoi(token);

                while (tc_no &&  current_tc_no != tc_no) {

                    /* skip to next test case */
                    while (( fget_ptr = fgets (line, sizeof(line), fp))) {

                             if (strncmp (line, ":TESTCASE-BEGIN:", strlen(":TESTCASE-BEGIN:"))) {
                                 continue;
                             }
                             break;
                    }

                    if (!fget_ptr) break;
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    current_tc_no = atoi(token);
                }
                
               if (!fget_ptr) break;

               /* Test case found */
                rc = sprintf(buff, "\n ***** Executing Test case : %s - %d ***** \n",
                                    file_name,  current_tc_no);
                printf("%s", buff);
                fwrite(buff, 1, rc, ut_log_file);
                fflush(ut_log_file);
                TC_RUNNING = true;
                tc_found = true;
            }



            else if (strncmp (line, ":TESTCASE-END:", strlen(":TESTCASE-END:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;

               /* Test case found */
                rc = sprintf(buff, "\n ***** Test case : %s - %d Finished ***** \n",
                                    file_name,  current_tc_no);
                printf("%s", buff);
                fwrite(buff, 1, rc, ut_log_file);

                tc_print_result(&result_head);
                tc_cleanup_result_list(&result_head);
                fflush(ut_log_file);

                if (  tc_no && TC_RUNNING ) {
                    break;
                }
            }



            else if (strncmp (line, ":DESC:", strlen(":DESC:")) == 0) {
                
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                rc = sprintf(buff, "Description : %s\n", token);
                 printf("%s", buff);
                 fwrite(buff, 1, rc, ut_log_file);
                 fflush(ut_log_file);
            }



            else if (strncmp (line, ":STEP:", strlen(":STEP:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                rc = sprintf(buff, "STEP : %s\n", token);
                printf("%s", buff);
                fwrite(buff, 1, rc, ut_log_file);
                fflush(ut_log_file);
                current_step_no = atoi(token);
            }



            else if (strncmp (line, ":CMD:", strlen(":CMD:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                rc = sprintf(buff, "CMD : %s\n", token);
                printf("%s", buff);
                fwrite(buff, 1, rc, ut_log_file);
                fflush(ut_log_file);
                status = parse_input_cmd(token, strlen(token), &is_repeat_cmd);
                assert(status == COMPLETE);

                /* block if it is show command */
                if (pattern_match(token, strlen(token), "show") && 
                        TC_RUNNING) {   /* You can load the cmds without testcase script */

                    if (ut_parser_debug) {
                        rc = sprintf(buff, "Waiting for backend data\n");
                        printf("%s", buff);
                        fwrite(buff, 1, rc, ut_log_file);
                    }

                    if ((ut_parser_recv_buff_data_size =
                             mq_timedreceive(UT_PARSER_MSG_Q_FD,
                                        ut_parser_recv_buff, MAX_MSG_SIZE, NULL,
                                        &mq_wait_time)) == -1) {

                            printf ("Msg Q  Time out : No Data Recvd from Backend\n");
                            rc += sprintf(buff, "Msg Q  Time out : No Data Recvd from Backend\n");
                            fwrite(buff, 1, rc, ut_log_file);
                            ut_parser_recv_buff_data_size = 0;
                            memset(ut_parser_recv_buff, 0, sizeof(ut_parser_recv_buff));
                    }

                    else if (ut_parser_debug) {

                        printf("Mq Data Recvd by UT Parser : \n");
                        printf("%s", ut_parser_recv_buff);
                        rc += sprintf(buff, "Mq Data Recvd by UT Parser : \n");
                        fwrite(buff, 1, rc, ut_log_file);
                        fwrite(ut_parser_recv_buff, 1, ut_parser_recv_buff_data_size, ut_log_file);
                    }
                }
                fflush(ut_log_file);
            }



            else if (strncmp (line, ":PATTERN-MATCH:", strlen(":PATTERN-MATCH:")) == 0) {

                int rc1 = 0;
                char pattern [256];
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;  // this is the pattern to be matched
                rc1 = sprintf(pattern + rc1, "%s", token);

                while(1) {
                    token = strtok(NULL, ":") ;
                    if (!token) break;
                    rc1 += sprintf(pattern + rc1, ":%s", token);
                }
              
                printf("pattern to be matched : |%s|\n", pattern);
                rc = sprintf(buff, "pattern to be matched : |");
                fwrite(buff, 1, rc, ut_log_file);
                fwrite(pattern, 1, rc1, ut_log_file);
                rc = sprintf(buff, "|\n");
                fwrite(buff, 1, rc, ut_log_file);

                if (pattern_match(ut_parser_recv_buff,  ut_parser_recv_buff_data_size, pattern)) {
                    printf("PASS\n");
                    rc = sprintf(buff, "PASS\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, true, true);
                }
                else {
                   printf("FAIL\n");
                   rc = sprintf(buff,  "FAIL\n");
                   fwrite(buff, 1, rc, ut_log_file);
                   tc_append_result(&result_head, current_step_no, false, true);
                }
                fflush(ut_log_file);
            }



            else if (strncmp (line, ":PATTERN-NOT-MATCH:", strlen(":PATTERN-NOT-MATCH:")) == 0) {

                int rc1 = 0;
                char pattern [256];
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;  // this is the pattern to be not matched
                rc1 += sprintf(pattern + rc1, "%s", token);

                while(1) {
                    token = strtok(NULL, ":") ;
                    if (!token) break;
                    rc1 += sprintf(pattern + rc1,  ":%s", token);
                }

                printf("pattern to be not matched : |%s|\n", pattern);
                rc = sprintf(buff, "pattern to be not matched : |");
                fwrite(buff, 1, rc, ut_log_file);
                fwrite(pattern, 1, rc1, ut_log_file);
                rc = sprintf(buff, "|\n");
                fwrite(buff, 1, rc, ut_log_file);

                if (!pattern_match(ut_parser_recv_buff, ut_parser_recv_buff_data_size, pattern)) {
                    printf("PASS\n");
                    rc = sprintf(buff, "PASS\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, true, false);
                }
                else {
                    printf("FAIL\n");
                    rc = sprintf(buff, "FAIL\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, false, false);
                }
                fflush(ut_log_file);
            }



            else if (strncmp (line, ":SLEEP:", strlen(":SLEEP:")) == 0) {

                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    rc = sprintf(buff, "Sleeping for %s sec\n", token);
                    printf("%s", buff);
                    fwrite(buff, 1, rc, ut_log_file);
                    fflush(ut_log_file);
                    sleep(atoi(token));
            }



            else if (strncmp (line, ":ABORT:", strlen(":ABORT:")) == 0) {
                    printf("Aborted\n");
                    rc = sprintf(buff, "Aborted\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    break;
            }



            else if (strncmp (line, ":PAUSE:", strlen(":PAUSE:")) == 0) {
                    printf("Paused\n");
                    rc = sprintf(buff, "Paused\n");
                    fwrite(buff, 1, rc, ut_log_file);
                     fflush(ut_log_file);
                    getchar();
            }



             else if (strncmp (line, ":GREP:", strlen(":GREP:")) == 0) {
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    printf ("Grep Pattern : %s\n", token);
                    rc = sprintf (buff, "Grep Pattern : %s\n", token);
                    fwrite(buff, 1, rc, ut_log_file);
                    ut_parser_recv_buff_data_size = 
                        grep (ut_parser_recv_buff, ut_parser_recv_buff_data_size, token);
                    printf ("Output After Grep : \n");
                    printf("%s", ut_parser_recv_buff);
                    rc = sprintf (buff, "Output After Grep : \n");
                    fwrite(buff, 1, rc, ut_log_file);
                    fwrite(ut_parser_recv_buff, 1, ut_parser_recv_buff_data_size, ut_log_file);
                    fflush(ut_log_file);
             }



             else if (strncmp (line, ":PRINT:", strlen(":PRINT:")) == 0) {
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    printf ("INFO : %s\n", token);
                    rc = sprintf (buff, "INFO : %s\n", token);
                    fwrite(buff, 1, rc, ut_log_file);
                    fflush(ut_log_file);
             }



            else if (strncmp (line, ":INT_STORE1:", strlen(":INT_STORE1:")) == 0) {

                    int index = 0;
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    index = atoi(token);
                    assert(index);
                    int_store1 = string_fetch_integer(ut_parser_recv_buff, 
                                        ut_parser_recv_buff_data_size, index);
                    printf("int_store1 = %lu at index %d\n", int_store1, index);
                    rc = sprintf (buff, "int_store1 = %lu at index %d\n", int_store1, index);
                    fwrite(buff, 1, rc, ut_log_file);
                     fflush(ut_log_file);
            }
            
            else if (strncmp (line, ":INT_STORE2:", strlen(":INT_STORE2:")) == 0) {

                    int index = 0;
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    index = atoi(token);
                    assert(index);
                    int_store2 = string_fetch_integer(ut_parser_recv_buff, 
                                        ut_parser_recv_buff_data_size, index);
                    printf("int_store2 = %lu at index %d\n", int_store2, index);
                    rc = sprintf (buff, "int_store2 = %lu at index %d\n", int_store2, index);
                    fwrite(buff, 1, rc, ut_log_file);
                    fflush(ut_log_file);
            }
            
            else if (strncmp (line, ":INT_STORE3:", strlen(":INT_STORE3:")) == 0) {

                    int index = 0;
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    index = atoi(token);
                    assert(index);
                    int_store3 = string_fetch_integer(ut_parser_recv_buff, 
                                        ut_parser_recv_buff_data_size, index);
                    printf("int_store3 = %lu at index %d\n", int_store3, index);
                    rc = sprintf (buff, "int_store3 = %lu at index %d\n", int_store3, index);
                    fwrite(buff, 1, rc, ut_log_file);
                     fflush(ut_log_file);
            }




    }

    fclose(fp);
    TC_RUNNING = false;
    fflush(ut_log_file);
    return tc_found;
}

static void
set_ut_debug_flag(char * ut_enable_flag) {

    if (strncmp(ut_enable_flag, "enable", strlen("enable")) == 0)
        ut_parser_debug = true;
    else
        ut_parser_debug = false;
}

/* This API is not used */
int
ut_test_handler (param_t *param, 
                            ser_buff_t *tlv_buf, 
                            op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    char *ut_file_name = NULL;
    char *ut_enable_flag = NULL;
    int tc_no = 0;
    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (strncmp(tlv->leaf_id, "ut-file-name", strlen("ut-file-name")) == 0)
            ut_file_name =  tlv->value;
        else if (strncmp(tlv->leaf_id, "tc-no", strlen("tc-no")) == 0)
            tc_no = atoi(tlv->value);
        else if (strncmp(tlv->leaf_id, "ut-enable", strlen("ut-enable")) == 0)
            ut_enable_flag = tlv->value;
    } TLV_LOOP_END;

    switch(cmdcode) {
        case  CMDCODE_RUN_UT_TC:
            run_test_case (ut_file_name, tc_no);
            break;
        case CMDCODE_DEBUG_UT:
            set_ut_debug_flag(ut_enable_flag);
            break;
        default : ;
    }
    return 0;
}

void
cli_out(unsigned char *buff, size_t buff_size) {

    if (!TC_RUNNING) {
        printf("%s", buff);
    }
    else {
        assert(buff_size < UT_PARSER_BUFF_MAX_SIZE);
         if (mq_send(UT_PARSER_MSG_Q_FD, (char *)buff , (buff_size + 1), 0) == -1 ) {
            printf ("mq_send failed on FD %d, errno = %d\n", UT_PARSER_MSG_Q_FD, errno);
         }
    }
}
