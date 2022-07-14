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

#include "libcliid.h"
#include "serialize.h"
#include <stdio.h>
#include "cmd_hier.h"
#include <stdlib.h>

#pragma pack (push,1)
typedef struct tlv_struct{
    leaf_type_t leaf_type;
    char leaf_id[LEAF_ID_SIZE];
    char value[LEAF_VALUE_HOLDER_SIZE];
} tlv_struct_t;
#pragma pack(pop)

#define EXTRACT_CMD_CODE(ser_buff_ptr)  \
    atoi(((tlv_struct_t *)(ser_buff_ptr->b) + (get_serialize_buffer_size(ser_buff_ptr)/sizeof(tlv_struct_t) -1))->value)

#define TLV_LOOP_BEGIN(ser_buff, tlvptr)                                                \
{                                                                                       \
    assert(ser_buff);                                                                   \
    tlvptr = (tlv_struct_t *)(ser_buff->b);                                             \
    unsigned int i = 0, k = get_serialize_buffer_size(ser_buff)/sizeof(tlv_struct_t);   \
    for(; i < k-1; i++, tlvptr++)

#define TLV_LOOP_END    }

#define tlv_copy_leaf_id(tlvptr, dst)                          \
    strncpy(dst, tlvptr->leaf_id, strlen(tlvptr->leaf_id));    \
    dst[strlen(tlvptr->leaf_id)] = '\0';


#define tlv_copy_leaf_value(tlvptr, dst)                         \
    strncpy(dst, tlvptr->value, strlen(tlvptr->value));          \
    dst[strlen(tlvptr->value)] = '\0';

#define collect_tlv(ser_buff, tlvptr)           \
    serialize_string(ser_buff, (char *)tlvptr, sizeof(tlv_struct_t))

#define prepare_tlv_from_leaf(leaf, tlvptr)    \
    tlvptr->leaf_type = leaf->leaf_type;       \
    strncpy(tlvptr->leaf_id, leaf->leaf_id, MIN(LEAF_ID_SIZE, strlen(leaf->leaf_id)));

#define put_value_in_tlv(tlvptr, _val)         \
    strncpy(tlvptr->value, _val, MIN(LEAF_VALUE_HOLDER_SIZE, strlen(_val)));

static inline void 
print_tlv_content(tlv_struct_t *tlv){

    if(!tlv)
        return;

    printf("tlv->leaf_type = %s\n", get_str_leaf_type(tlv->leaf_type));
    printf("tlv->leaf_id   = %s\n", tlv->leaf_id);
    printf("tlv->value     = %s\n", tlv->value);
}

static inline void
dump_tlv_serialized_buffer(ser_buff_t *tlv_ser_buff){

    tlv_struct_t *tlv = NULL;

    printf("cmd code = %d\n", EXTRACT_CMD_CODE(tlv_ser_buff));
    TLV_LOOP_BEGIN(tlv_ser_buff, tlv){
        print_tlv_content(tlv);
        printf("\n");
    } TLV_LOOP_END;
}

static inline void
swap_tlv_units(tlv_struct_t *tlv1, tlv_struct_t *tlv2){
    
    tlv_struct_t tlv;
    tlv = *tlv1;
    *tlv1 = *tlv2;
    *tlv2 = tlv;
}
#endif /* __CMDTLV__H */
