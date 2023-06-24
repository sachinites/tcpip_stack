#include <time.h>
#include "timedef.h"
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"

#define CMDCODE_CONFIG_TIME_RANGE 1

struct time_range_ {

    
} ;

static int time_range_config_handler(param_t *param,
                                ser_buff_t *tlv_buf,
                                op_mode enable_or_disable) {

    return 0;
}

static void
 time_input_cli (param_t *root) {

    {
        param_t *dd_mm_yyyy = (param_t *)calloc (1, sizeof(param_t));
        init_param(dd_mm_yyyy, LEAF, 0, time_range_config_handler, 0, STRING, "dd-mm-yyyy", "DD-MM-YYYY");
        libcli_register_param(root, dd_mm_yyyy);
       libcli_set_param_cmd_code(dd_mm_yyyy, CMDCODE_CONFIG_TIME_RANGE);
       {
           param_t *hh_mm = (param_t *)calloc(1, sizeof(param_t));
           init_param(hh_mm, LEAF, 0, time_range_config_handler, 0, STRING, "hh::mm", "hh-mm format Eg16::30");
           libcli_register_param(dd_mm_yyyy, hh_mm);
           libcli_set_param_cmd_code(hh_mm, CMDCODE_CONFIG_TIME_RANGE);
       }
    }

 }


void
time_range_config_cli_tree (param_t *root) {

    {
        /* conf node <node-name> time-range ...*/
        static param_t time_range;
        init_param(&time_range, CMD, "time-range", NULL, 0, INVALID, 0, "time-range");
        libcli_register_param(root, &time_range);
        {
             /* conf node <node-name> time-range <time-range-name> ...*/
             static param_t time_range_name;
             init_param(&time_range_name, LEAF, 0, NULL, 0, STRING, "timer-range-name", "time-range name");
             libcli_register_param(&time_range, &time_range_name);
             {
                 /* conf node <node-name> time-range <time-range-name> absolute ...*/
                 static param_t absolute;
                 init_param(&absolute, CMD, "absolute", NULL, 0, INVALID, 0, "time-range-type");
                 libcli_register_param(&time_range_name, &absolute);
                 {
                     /* conf node <node-name> time-range <time-range-name> absolute start ...*/
                     static param_t start;
                     init_param(&start, CMD, "start", NULL, 0, INVALID, 0, "start time");
                     libcli_register_param(&absolute, &start);
                     {
                        time_input_cli (&start);
                     }
                 }
                 {
                     /* conf node <node-name> time-range <time-range-name> absolute end ...*/
                     static param_t end;
                     init_param(&end, CMD, "end", NULL, 0, INVALID, 0, "end time");
                     libcli_register_param(&absolute, &end);
                     {
                         time_input_cli(&end);
                     }
                 }
             }
        }
    }
}
