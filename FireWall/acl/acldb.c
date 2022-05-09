#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../../graph.h"
#include "acldb.h"
#include "../mtrie/mtrie.h"

acl_proto_t
acl_string_to_proto(unsigned char *proto_name) {

    /* To be replaced with hashmap when code is converted into C++ */
    if (strncmp(proto_name, "ip", 2) == 0) {
        return ACL_IP;
    }

    if (strncmp(proto_name, "udp", 3) == 0) {
        return ACL_UDP;
    }

    if (strncmp(proto_name, "tcp", 3) == 0) {
        return ACL_TCP;
    }

    if (strncmp(proto_name, "icmp", 4) == 0) {
        return ACL_ICMP;
    }

    return ACL_PROTO_NONE;
}

void 
acl_entry_free(acl_entry_t *acl_entry) {

}

/* Convert the ACL entry into TCAM entry format */
void
acl_compile (acl_entry_t *acl_entry) {

    bool rc;
    uint32_t temp4;
    uint16_t temp2;
    uint16_t bytes_copied = 0;

    bitmap_t *prefix = &acl_entry->prefix;
    bitmap_t *mask = &acl_entry->mask;

    uint8_t *prefix_pos = (uint8_t *)prefix->bits;
    uint8_t *mask_pos = (uint8_t *)mask->bits;
    
    /* Protocol 1 B*/
    *prefix_pos = (uint8_t )(acl_entry->proto);
    *mask_pos = 0;
    prefix_pos++; mask_pos++; bytes_copied++;

    /* Src ip Address & Mask */
    memcpy((char *)prefix_pos, (char *)&acl_entry->saddr.ip4.prefix, 4);
    temp4 = ~acl_entry->saddr.ip4.mask;
    memcpy((char *)mask_pos, (char *)&temp4, 4);
    prefix_pos+=4; mask_pos+= 4; bytes_copied +=4;

    /* Src Port Range */
    /* Not Supported Yet, fill it 16bit prefix as zero, and 16 bit mask as  all 1s */
    temp2 = 0;
    memcpy((char *)prefix_pos, (char *)&temp2, 2);
    temp2 = ~temp2;
    memcpy((char *)mask_pos, (char *)&temp2, 2);
    prefix_pos+=2; mask_pos+= 2; bytes_copied +=2;

     /* Dst ip Address & Mask */
    memcpy((char *)prefix_pos, (char *)&acl_entry->daddr.ip4.prefix, 4);
    temp4 = ~acl_entry->daddr.ip4.mask;
    memcpy((char *)mask_pos, (char *)&temp4, 4);
    prefix_pos+=4; mask_pos+= 4; bytes_copied +=4;

    /* Drt Port Range */
    /* Not Supported Yet, fill it 16bit prefix as zero, and 16 bit mask as  all 1s */
    temp2 = 0;
    memcpy((char *)prefix_pos, (char *)&temp2, 2);
    temp2 = ~temp2;
    memcpy((char *)mask_pos, (char *)&temp2, 2);
    prefix_pos+=2; mask_pos+= 2; bytes_copied +=2;

    /* Fill the residual bits : prefix with Zeros, and Mask with 1s*/
    
    // Prefix : Already done

    // Mask :
    uint16_t bits_copied = bytes_copied * 8;
    temp4 = 0;
    ITERATE_BITMAP_BEGIN(mask, bits_copied, temp2, rc) {
        bitmap_set_bit_at(mask, temp2); // temp2 is used as an index
        temp4++;
    } ITERATE_BITMAP_END;

    prefix->next = (bytes_copied * 8) + temp4;
    mask->next = prefix->next;

    assert(prefix->next == ACL_PREFIX_LEN);
}

access_list_t *
acl_lookup_access_list(node_t *node, char *access_list_name) {

    glthread_t *curr;
    access_list_t *acc_lst;
    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        acc_lst = glthread_to_access_list(curr);
        if (strncmp(acc_lst->name, 
                           access_list_name, 
                            ACCESS_LIST_MAX_NAMELEN) == 0) {
            return acc_lst;
        }
    } ITERATE_GLTHREAD_END(&node->access_lists_db, curr);

    return NULL;
}

access_list_t *
acl_create_new_access_list(char *access_list_name) {

    access_list_t *acc_lst = (access_list_t *)calloc(1, sizeof(access_list_t));

    strncpy(acc_lst->name, access_list_name, ACCESS_LIST_MAX_NAMELEN);
    init_glthread(&acc_lst->head);
    init_glthread(&acc_lst->glue);
    acc_lst->mtrie = (mtrie_t *)calloc(1, sizeof(mtrie_t));
    init_mtrie(acc_lst->mtrie, ACL_PREFIX_LEN);
    acc_lst->ref_count = 0;
    return acc_lst;
}

void
access_list_add_acl_entry(
                                access_list_t * access_list,
                                acl_entry_t *acl_entry) {

    glthread_add_last(&access_list->head, &acl_entry->glue);
}


bool
acl_install(access_list_t *access_list, acl_entry_t *acl_entry) {

     return mtrie_insert_prefix(
                    access_list->mtrie, 
                    &acl_entry->prefix,
                    &acl_entry->mask,
                    ACL_PREFIX_LEN,
                    (void *)acl_entry);
 }

 void access_list_free(access_list_t *access_list) {


 }

bool
acl_process_user_config(node_t *node, 
                char *access_list_name,
                acl_entry_t *acl_entry) {

    bool rc = false;
    access_list_t *access_list;
    bool new_access_list = false;

    acl_compile (acl_entry);

    access_list = acl_lookup_access_list(node, access_list_name);

    if (!access_list) {
        access_list = acl_create_new_access_list(access_list_name);
        new_access_list = true;
    }

    rc = acl_install(access_list, acl_entry);

    if (!rc) {
        printf ("Error : ACL Installation into Mtrie Failed\n");
        if (new_access_list) {
            access_list_free(access_list);
        }
        return false;
    }

    access_list_add_acl_entry(access_list, acl_entry);

    if (new_access_list) {
        glthread_add_next(&node->access_lists_db, &access_list->glue);
    }

    return true;
}

static void
bitmap_fill_with_params(
        bitmap_t *bitmap,
        uint8_t proto,
        uint32_t src_addr,
        uint32_t dst_addr,
        uint16_t src_port,
        uint16_t dst_port) {

        uint8_t *ptr1 = (uint8_t *)(bitmap->bits);

        *ptr1 = proto;
        ptr1++;

        uint32_t *ptr4 = (uint32_t *)ptr1;
        *ptr4 = src_addr;
        ptr4++;

        uint16_t *ptr2 = (uint16_t *)ptr4;
        *ptr2 = src_port;
        ptr2++;

        ptr4 = (uint32_t *)ptr2;

        *ptr4 = dst_addr;
        ptr4++;

        ptr2 = (uint16_t *)ptr4;
        *ptr2 = dst_port;
  }

acl_action_t
access_list_evaluate (access_list_t *acc_lst,
                                uint8_t proto,
                                uint32_t src_addr,
                                uint32_t dst_addr,
                                uint16_t src_port, 
                                uint16_t dst_port) {

    acl_entry_t *hit_acl = NULL;
    mtrie_node_t *hit_node = NULL;

    bitmap_t input;
    bitmap_init(&input, ACL_PREFIX_LEN);

    bitmap_fill_with_params(&input, proto, src_addr, dst_addr, src_port, dst_port);

    hit_node = mtrie_longest_prefix_match_search(acc_lst->mtrie, &input);

    /* Deny by default */
    if (!hit_node) {
        ACL_DENY;
    }

    hit_acl = (acl_entry_t *)(hit_node->data);
    assert(hit_acl);

    hit_acl->hit_count++;
    return hit_acl->action;
}