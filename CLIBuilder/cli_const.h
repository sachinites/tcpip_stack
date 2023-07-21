#ifndef __CLICNST__
#define __CLICNST__

#include <stddef.h>

#define MAX_COMMAND_LENGTH 256

#define DEF_CLI_HDR  "Soft-Firewall>$ "
#define CMD_NAME_SIZE   32
#define LEAF_VALUE_HOLDER_SIZE 64
#define LEAF_ID_SIZE    32
#define PARAM_HELP_STRING_SIZE 64
#define MAX_OPTION_SIZE 16
#define MAX_CMD_TREE_DEPTH 24
#define CHILDREN_START_INDEX    0
#define CHILDREN_END_INDEX      (MAX_OPTION_SIZE -1)
#define TLV_MAX_BUFFER_SIZE     1024
#define POSSIBILITY_ARRAY_SIZE  10
#define CLI_HDR_MAX_SIZE    32
#define LEAF_REG_EX_MAX_LEN 32
#define KEY_BACKSPACE_MOBAXTERM 8 /* I found, in MobaXterm on Windows, BS has ascii of 8*/
#define KEY_ASCII_TAB   9
#define KEY_ASCII_NEWLINE 10
#define KEY_ASCII_SPACE   32
#define KEY_ASCII_DOUBLE_QUOTES 34

#define CLI_HISTORY_LIMIT   50

#define NEGATE_CHARACTER "no"



typedef enum{
    CONFIG_DISABLE,
    CONFIG_ENABLE,
    OPERATIONAL,
    MODE_UNKNOWN
} op_mode;

/* Pls refer to leaf_type_handler leaf_handler_array[ ] array
    should you choose to update/modify the ordering of these enums*/
typedef enum leaf_type_{
    INT,
    STRING,
    IPV4,
    FLOAT,
    IPV6,
    BOOLEAN,
    INVALID,
    LEAF_TYPE_MAX
} leaf_type_t;

static const char *
get_str_leaf_type(leaf_type_t leaf_type)
{

    switch (leaf_type)
    {   
    case INT:
        return "INT";
    case STRING:
        return "STRING";
    case IPV4:
        return "IPV4";
    case FLOAT:
        return "FLOAT";
    case IPV6:
        return "IPV6";
    case BOOLEAN:
        return "BOOLEAN";
    case LEAF_TYPE_MAX:
        return "LEAF_TYPE_MAX";
    default:
        return "Unknown";
    }   
    return NULL;
}

typedef enum{
    LEAF_VALIDATION_FAILED = -1, 
    LEAF_VALIDATION_SUCCESS
} leaf_validation_rc_t;

#define MODE_CHARACTER  '/'
#define SUBOPTIONS_CHARACTER '?'
#define CMD_EXPANSION_CHARACTER '.'
#define NEGATE_CHARACTER "no"


/* Reserved TLV Types */
#define TLV_TYPE_NORMAL    0           /* Normal TLVs which store user CLI values */
#define TLV_TYPE_CMD_NAME    255  /* TLVs which store CMD params name*/
#define TLV_TYPE_NEGATE    254          /* 'no' keyword */


/* Ncurses Color indexes */
#define GRASS_PAIR     1
#define WATER_PAIR     2
#define MOUNTAIN_PAIR  3
#define PLAYER_PAIR    4
#define RED_ON_BLACK 5
#define GREEN_ON_BLACK 6

#endif 