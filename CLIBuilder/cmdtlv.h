/*
 * =====================================================================================
 *
 *       Filename:  cmdtlv.h
 *
 *    Description:  TLV implementation on top of serialized library
 *
 *        Version:  1.0
 *        Created:  Friday 04 August 2017 03:59:45  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */


#ifndef __CMDTLV__H
#define __CMDTLV__H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ncurses.h>
#include "cli_const.h"
#include "string_util.h"

#pragma pack (push,1)
typedef struct tlv_struct{
    uint8_t tlv_type;
    leaf_type_t leaf_type;
    unsigned char leaf_id[LEAF_ID_SIZE];
    unsigned char value[LEAF_VALUE_HOLDER_SIZE];
} tlv_struct_t;
#pragma pack(pop)

#define TLV_LOOP_STACK_BEGIN(stack_ptr, tlvptr)      \
{                                                                                              \
    tlvptr = (tlv_struct_t *)(stack_ptr->slot[0]);                       \
    int _i = 0;                                                             \
    for(; _i <= stack_ptr->top; _i++, tlvptr = (tlv_struct_t *)(stack_ptr->slot[_i]))

#define TLV_LOOP_END    }

#define tlv_copy_leaf_id(tlvptr, dst)                          \
    strncpy((char *)dst, tlvptr->leaf_id, strlen(tlvptr->leaf_id));    \
    dst[strlen(tlvptr->leaf_id)] = '\0';

#define tlv_copy_leaf_value(tlvptr, dst)                         \
    strncpy((char *)dst, tlvptr->value, strlen(tlvptr->value));          \
    dst[strlen(tlvptr->value)] = '\0';

#define prepare_tlv_from_leaf(leaf, tlvptr)    \
    tlvptr->tlv_type = TLV_TYPE_NORMAL; \
    tlvptr->leaf_type = leaf->leaf_type;       \
    strncpy((char *)tlvptr->leaf_id, leaf->leaf_id, MIN(LEAF_ID_SIZE, strlen(leaf->leaf_id)));

#define put_value_in_tlv(tlvptr, _val)         \
	{										   \
		const char *temp = _val;			   \
		strncpy((char *)tlvptr->value, temp, LEAF_VALUE_HOLDER_SIZE);	\
	}

static inline void 
print_tlv_content (tlv_struct_t *tlv){

    if(!tlv)
        return;

    //cprintf ("\ntlv->tlv_type = %d", tlv->tlv_type);
    //cprintf("\ntlv->leaf_type = %s", get_str_leaf_type(tlv->leaf_type));
    //cprintf("\ntlv->leaf_id   = %s", tlv->leaf_id);
    //cprintf("\ntlv->value     = %s", tlv->value);
}

#endif /* __CMDTLV__H */
