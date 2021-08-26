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
#include "../../../gluethread/glthread.h"
#include "../../css.h"
#include "../../libcli.h"
#include "../../cmdtlv.h"

/* Global variables for UT parser */
static int UT_PARSER_MSG_Q_FD; 
static bool TC_RUNNING = false;
static unsigned char ut_parser_recv_buff[2048];
static int ut_parser_recv_buff_data_size;
static sem_t wait_for_data_sema;
static bool ut_parser_debug = false;
static FILE *ut_log_file = NULL;

#define MAX_MESSAGES    1
#define MAX_MSG_SIZE       2048
#define QUEUE_PERMISSIONS   0660

extern CMD_PARSE_STATUS
parse_input_cmd(char *input, unsigned int len, bool *is_repeat_cmd);

static void *
 ut_parser_data_recvr_thread_fn(void *arg) {

    struct mq_attr attr;
    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;

   if ((UT_PARSER_MSG_Q_FD  = mq_open ("/ut_parser_msg_q", 
                        O_RDWR | O_CREAT, 
                        QUEUE_PERMISSIONS, &attr)) == -1) {

        printf ("UT Parser mq_open failed, errno = %d\n", errno);
        exit (1);
    }

    while (1)
    {
        if (mq_receive(UT_PARSER_MSG_Q_FD, 
                                 ut_parser_recv_buff, MAX_MSG_SIZE, NULL) == -1)
        {
            printf("mq_receive error, errno = %d\n", errno);
            exit(1);
        }
        sem_post(&wait_for_data_sema);
        if (ut_parser_debug) {
            printf("Mq Data Recvd by UT Parser : \n");
            printf("%s", ut_parser_recv_buff);
        }
    }

    return NULL;
 }

static void
ut_parser_run_data_recvr_thread() {

    pthread_attr_t attr;
    static pthread_t ut_parser_data_recvr_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&ut_parser_data_recvr_thread, &attr, 
                    ut_parser_data_recvr_thread_fn, 
                    NULL);
}

void
ut_parser_init ( ) {

       ut_parser_run_data_recvr_thread();
       sem_init(&wait_for_data_sema, 0, 0); /* Zero semaphore */
       ut_log_file = fopen ("CommandParser/ut/utinfra/ut_log_file.txt", "w");
       assert(ut_log_file);
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

    tc_result_t *res = calloc(1, sizeof(tc_result_t));
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

    rc = sprintf(buff, "\n****  Result ******\n");
    printf("%s", buff);
    fwrite(buff, 1, rc, ut_log_file);

    ITERATE_GLTHREAD_BEGIN(head, curr) {

        res = glue_to_tc_result(curr);
        rc = sprintf(buff, "%s  STEP: %d : %s\n", 
            res->pattern_match ? "pattern-present" : "pattern-not-present",
            res->step_no, res->pass ? "PASS" : "FAIL");
        printf("%s", buff);
        fwrite(buff, 1, rc, ut_log_file);
    } ITERATE_GLTHREAD_END(head, curr);
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
run_test_case(unsigned char *file_name, uint16_t tc_no) {

    int rc = 0;
    char *fget_ptr;
    uint16_t current_step_no;
    uint16_t current_tc_no;
    char *token;
    unsigned char line[512];
    bool is_repeat_cmd = false;
    glthread_t result_head;
    bool tc_found = false;
    char buff[128];
    CMD_PARSE_STATUS status = UNKNOWN;
    
     fget_ptr = NULL;
    init_glthread(&result_head);

    FILE *fp = fopen (file_name, "r");
    assert(fp);

    while ( fget_ptr = fgets (line, sizeof(line), fp) ) {

            if (line[0] != ':') continue;

            /* Remove \n */
            strtok(line, "\n");

            if (strncmp (line, ":TESTCASE-BEGIN:", strlen(":TESTCASE-BEGIN:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;

                current_tc_no = atoi(token);

                while (tc_no &&  current_tc_no != tc_no) {

                    /* skip to next test case */

                    while ( fget_ptr = fgets (line, sizeof(line), fp)) {

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
                rc = sprintf(buff, "\n ***** Executing Test case : %s - %d ***** \n", file_name,  current_tc_no);
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
                rc = sprintf(buff, "\n ***** Test case : %s - %d Finished ***** \n", file_name,  current_tc_no);
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
                current_step_no = atoi(token);
            }


            else if (strncmp (line, ":CMD:", strlen(":CMD:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                rc = sprintf(buff, "CMD : %s\n", token);
                printf("%s", buff);
                fwrite(buff, 1, rc, ut_log_file);
                status = parse_input_cmd(token, strlen(token), &is_repeat_cmd);
                assert(status == COMPLETE);

                /* block if it is show command */
                if (pattern_match(token, strlen(token), "show")) {
                    if (ut_parser_debug) {
                        rc = sprintf(buff, "Waiting for backend data\n");
                        printf("%s", buff);
                        fwrite(buff, 1, rc, ut_log_file);
                    }
                    sem_wait(&wait_for_data_sema);
                    if (ut_parser_debug) {
                        rc = sprintf(buff, "backend data Recvd, Woken Up\n");
                        printf("%s", buff);
                        fwrite(buff, 1, rc, ut_log_file);
                    }
                }
                fflush(ut_log_file);
            }


            else if (strncmp (line, ":pattern-present:", strlen(":pattern-present:")) == 0) {

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


                if (pattern_match(ut_parser_recv_buff, ut_parser_recv_buff_data_size, pattern)) {
                    printf(ANSI_COLOR_GREEN "PASS\n" ANSI_COLOR_RESET);
                    rc = sprintf(buff, "PASS\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, true, true);
                }
                else {
                   printf(ANSI_COLOR_RED "FAIL\n" ANSI_COLOR_RESET);
                   rc = sprintf(buff,  "FAIL\n");
                   fwrite(buff, 1, rc, ut_log_file);
                   tc_append_result(&result_head, current_step_no, false, true);
                }
                memset(ut_parser_recv_buff, 0, ut_parser_recv_buff_data_size);
                fflush(ut_log_file);
            }


            else if (strncmp (line, ":pattern-not-present:", strlen(":pattern-not-present:")) == 0) {

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
                    printf(ANSI_COLOR_GREEN "PASS\n" ANSI_COLOR_RESET);
                    rc = sprintf(buff, "PASS\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, true, false);
                }
                else {
                    printf(ANSI_COLOR_RED "FAIL\n" ANSI_COLOR_RESET);
                    rc = sprintf(buff, "FAIL\n");
                    fwrite(buff, 1, rc, ut_log_file);
                    tc_append_result(&result_head, current_step_no, false, false);
                }
                memset(ut_parser_recv_buff, 0, ut_parser_recv_buff_data_size);
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
                    getchar();
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
    char *ut_enable_flag = false;
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
         if (mq_send(UT_PARSER_MSG_Q_FD, buff , buff_size + 1, 0) == -1 ) {
            printf ("mq_send failed on FD %d, errno = %d\n", UT_PARSER_MSG_Q_FD, errno);
         }
    }
}