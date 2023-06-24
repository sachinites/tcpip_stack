#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <ncurses.h>
#include "../../stack/stack.h"
#include "clistd.h"
#include "CmdTree.h"
#include "../KeyProcessor/KeyProcessor.h"
#include "../cmdtlv.h"
#include "../string_util.h"

extern int cprintf (const char* format, ...) ;

/* Standard Validations Begin*/

typedef leaf_validation_rc_t (*leaf_type_handler)(char *value_passed);

static int
ip_version(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return 4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return 6;
    }
    return -1;
}

static leaf_validation_rc_t
ipv4_validation_handler (char *value_passed){

    if (ip_version ((const char *)value_passed) == 4) 
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static leaf_validation_rc_t
ipv6_validation_handler(char *value_passed){

    if (ip_version ((const char *)value_passed) == 6) 
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static leaf_validation_rc_t
int_validation_handler(char *value_passed){

    if (value_passed == NULL || *value_passed == '\0')
        return LEAF_VALIDATION_FAILED; 

    // Check if the first character is a valid sign (+ or -)
    if (*value_passed == '+' || *value_passed == '-')
        value_passed++; // Skip the sign

    // Check each remaining character
    while (*value_passed != '\0') {

        if (!isdigit(*value_passed))
            return LEAF_VALIDATION_FAILED;

        value_passed++;
    }

    return LEAF_VALIDATION_SUCCESS;
}

static leaf_validation_rc_t
string_validation_handler(char *value_passed){

     return LEAF_VALIDATION_SUCCESS;
}

static int 
isFloat(const char *input) {
    // Check if the input is empty
    if (input == NULL || *input == '\0')
        return 0; // Not a float

    // Check if the first character is a valid sign (+ or -)
    if (*input == '+' || *input == '-')
        input++; // Skip the sign

    int dotCount = 0;

    // Check each remaining character
    while (*input != '\0') {
        if (*input == '.') {
            dotCount++;

            // Check if there is more than one dot
            if (dotCount > 1)
                return 0; // Not a float
        }
        else if (!isdigit(*input))
            return 0; // Not a float

        input++;
    }

    // Check if the float ends with a dot
    if (*(input - 1) == '.')
        return 0; // Not a float

    return 1; // Input is a float
}

static leaf_validation_rc_t
float_validation_handler(char *value_passed){

     if (isFloat ((const char *)value_passed) == 1) {
        return LEAF_VALIDATION_SUCCESS;
     }
     return LEAF_VALIDATION_FAILED;
}

static leaf_validation_rc_t 
boolean_validation_handler(char *value_passed){

     return LEAF_VALIDATION_SUCCESS;
}

static leaf_type_handler leaf_handler_array[LEAF_TYPE_MAX] = {

    int_validation_handler,
    string_validation_handler,
    ipv4_validation_handler,
    float_validation_handler,
    ipv6_validation_handler,
    boolean_validation_handler,
    NULL
};

extern leaf_validation_rc_t
clistd_validate_leaf (tlv_struct_t *tlv) {

    if (leaf_handler_array[tlv->leaf_type]) {
        return leaf_handler_array[tlv->leaf_type]((char *)tlv->value);
    }
    return LEAF_VALIDATION_SUCCESS;
}


/* Standard Validations End */

int
clistd_config_device_default_handler (int cmdcode,  Stack_t *tlv_stack, op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(enable_or_disable == CONFIG_ENABLE) {
            cli_set_hdr (cli_get_default_cli(), tlv->value, strlen ((const char *)tlv->value));
        }
        else{
            cli_set_hdr (cli_get_default_cli(),  (unsigned char *)DEF_CLI_HDR, strlen ((const char *)DEF_CLI_HDR));
        }

    }TLV_LOOP_END;

    return 0;
}

int
show_help_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable){

    attron(COLOR_PAIR(GREEN_ON_BLACK));
    cprintf("\nWelcome to Help Wizard\n");
    cprintf("========================\n");
    cprintf("1. Use %c Character after the command to enter command mode\n", MODE_CHARACTER);
    cprintf("2. Use %c Character after the command to see possible follow up suboptions\n", SUBOPTIONS_CHARACTER);
    cprintf("3. Use %c Character after the command to see possible complete command completions\n", CMD_EXPANSION_CHARACTER);
    cprintf("4. [ ctrl + l ] - clear screen\n");
    cprintf("5. [ ctrl + t ] - jump to top of cmd tree\n");
    cprintf("6. [ BackSpace ] - Erase the last word\n");
    cprintf("7. [ Page Up  Or  ctrl + ']' ] - Move one Level Up in the cmd tree\n");
    cprintf("8. config [ %s ] console name <console name> - set/unset new console name\n", NEGATE_CHARACTER);
    cprintf("9. [UP DOWN Arrow] - show the command history\n");
    attroff(COLOR_PAIR(GREEN_ON_BLACK));
    attron(COLOR_PAIR(PLAYER_PAIR));
    cprintf( "          Author : Abhishek Sagar\n");
    cprintf( "          Visit : www.csepracticals.com for more courses and projects\n");
    attroff(COLOR_PAIR(PLAYER_PAIR));
    return 0;
}

int
show_history_handler (int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    cli_history_show ();
    return 0;
}

int
cli_terminate_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable){

    endwin();
    cprintf("Bye Bye\n");
    exit(0);
}
