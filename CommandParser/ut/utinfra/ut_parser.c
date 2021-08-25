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
#include <sys/stat.h>
#include <mqueue.h>
#include <errno.h>
#include <semaphore.h>
#include "../../../gluethread/glthread.h"
#include "../../css.h"
#include "../../libcli.h"
#include "../../cmdtlv.h"

int UT_PARSER_MSG_Q_FD;
bool TC_RUNNING = false;
unsigned char ut_parser_recv_buff[2048];
int ut_parser_recv_buff_data_size;
sem_t wait_for_data_sema;
bool ut_parser_debug = false;

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
}

typedef struct tc_result_ {

    uint16_t step_no;
    bool pass;
    glthread_t glue;
} tc_result_t;
GLTHREAD_TO_STRUCT(glue_to_tc_result, tc_result_t, glue);

static void
tc_append_result(glthread_t *head, uint16_t step_no, bool pass) {

    tc_result_t *res = calloc(1, sizeof(tc_result_t));
    res->step_no = step_no;
    res->pass = pass;
    init_glthread(&res->glue);
    glthread_add_last(head, &res->glue);
}

static void
tc_print_result (glthread_t *head) {

    glthread_t *curr;
    tc_result_t *res;

    printf("\n****  Result ******\n");
    ITERATE_GLTHREAD_BEGIN(head, curr) {

        res = glue_to_tc_result(curr);
        printf("STEP: %d : %s\n", res->step_no, res->pass ? "PASS" : "FAIL");
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

void
run_test_case(unsigned char *file_name, uint16_t tc_no) {

    uint16_t current_step_no;
    char *token;
    unsigned char line[512];
    bool is_repeat_cmd = false;
    glthread_t result_head;
    CMD_PARSE_STATUS status = UNKNOWN;
    
    TC_RUNNING = true;
    init_glthread(&result_head);

    FILE *fp = fopen (file_name, "r");
    assert(fp);

    while ( fgets (line, sizeof(line), fp) !=NULL ) {

            if (line[0] != ':') continue;

            /* Remove \n */
            strtok(line, "\n");

            if (strncmp (line, ":TESTCASE-BEGIN:", strlen(":TESTCASE-BEGIN:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;

                while (atoi(token) != tc_no) {

                    /* skip to next test case */

                    while ( fgets (line, sizeof(line), fp) !=NULL ) {

                             if (strncmp (line, ":TESTCASE-BEGIN:", strlen(":TESTCASE-BEGIN:"))) {
                                 continue;
                             }

                             break;
                    }
                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                }
               
               /* Test case found */
                printf("\n ***** Executing Test case : %s - %d ***** \n", file_name, tc_no);
            }


            else if (strncmp (line, ":TESTCASE-END:", strlen(":TESTCASE-END:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;

                assert(atoi(token) == tc_no);
               
               /* Test case found */
                printf("\n ***** Test case : %s - %d Finished ***** \n", file_name, tc_no);
            }


            else if (strncmp (line, ":DESC:", strlen(":DESC:")) == 0) {
                
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                printf("Description : %s\n", token);
            }


            else if (strncmp (line, ":STEP:", strlen(":STEP:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                printf("STEP : %s\n", token);
                current_step_no = atoi(token);
            }


            else if (strncmp (line, ":CMD:", strlen(":CMD:")) == 0) {

                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;
                printf("CMD : %s\n", token);
                status = parse_input_cmd(token, strlen(token), &is_repeat_cmd);
                assert(status == COMPLETE);

                /* block if it is show command */
                if (pattern_match(token, strlen(token), "show")) {
                    if (ut_parser_debug) {
                    printf("Waiting for backend data\n");
                    }
                    sem_wait(&wait_for_data_sema);
                    if (ut_parser_debug) {
                    printf("backend data Recvd, Woken Up\n");
                    }
                }
            }


            else if (strncmp (line, ":pattern-present:", strlen(":pattern-present:")) == 0) {

                int rc = 0;
                char pattern [256];
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;  // this is the pattern to be matched
                rc += snprintf(pattern + rc, sizeof(pattern), "%s", token);

                while(1) {
                    token = strtok(NULL, ":") ;
                    if (!token) break;
                    rc += snprintf(pattern + rc, sizeof(pattern), ":%s", token);
                }
              
                printf("pattern to be matched : |%s|\n", pattern);
                

                if (pattern_match(ut_parser_recv_buff, ut_parser_recv_buff_data_size, pattern)) {
                    printf(ANSI_COLOR_GREEN "PASS\n" ANSI_COLOR_RESET);
                    tc_append_result(&result_head, current_step_no, true);
                }
                else {
                   printf(ANSI_COLOR_RED "FAIL\n" ANSI_COLOR_RESET);
                   tc_append_result(&result_head, current_step_no, false);
                }
                memset(ut_parser_recv_buff, 0, ut_parser_recv_buff_data_size);
            }


            else if (strncmp (line, ":pattern-not-present:", strlen(":pattern-not-present:")) == 0) {

                int rc = 0;
                char pattern [256];
                token = strtok(line, ":") ;
                token = strtok(NULL, ":") ;  // this is the pattern to be not matched
                rc += snprintf(pattern + rc, sizeof(pattern), "%s", token);

                while(1) {
                    token = strtok(NULL, ":") ;
                    if (!token) break;
                    rc += snprintf(pattern + rc, sizeof(pattern), ":%s", token);
                }

                printf("pattern to be not matched : |%s|\n", pattern);

                if (!pattern_match(ut_parser_recv_buff, ut_parser_recv_buff_data_size, pattern)) {
                    printf(ANSI_COLOR_GREEN "PASS\n" ANSI_COLOR_RESET);
                    tc_append_result(&result_head, current_step_no, true);
                }
                else {
                    printf(ANSI_COLOR_RED "FAIL\n" ANSI_COLOR_RESET);
                    tc_append_result(&result_head, current_step_no, false);
                }
                memset(ut_parser_recv_buff, 0, ut_parser_recv_buff_data_size);
            }



            else if (strncmp (line, ":SLEEP:", strlen(":SLEEP:")) == 0) {

                    token = strtok(line, ":") ;
                    token = strtok(NULL, ":") ;
                    printf("Sleeping for %s sec\n", token);
                    sleep(atoi(token));
            }
    }

    tc_print_result(&result_head);
    tc_cleanup_result_list(&result_head);

    fclose(fp);
    TC_RUNNING = false;
}

/* This API is not used */
int
ut_test_handler (param_t *param, 
                            ser_buff_t *tlv_buf, 
                            op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    char *ut_file_name = NULL;
    int tc_no = 0;
    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (strncmp(tlv->leaf_id, "ut-file-name", strlen("ut-file-name")) == 0)
            ut_file_name =  tlv->value;
        else if (strncmp(tlv->leaf_id, "tc-no", strlen("tc-no")) == 0)
            tc_no = atoi(tlv->value);
    } TLV_LOOP_END;

    switch(cmdcode) {
        case  CMDCODE_RUN_UT_TC:
            run_test_case (ut_file_name, tc_no);
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