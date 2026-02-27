#include <stdio.h>
#include <stdint.h>
#include "nexthop.h"
#include "../../utils.h"
#include "../mpls_fwd.h"

int nh_flush_nexthops(nexthop_t **nexthop)
{

    int i = 0;
    int count = 0;

    if (!nexthop)
        return 0;

    for (; i < MAX_NXT_HOPS; i++)
    {

        if (nexthop[i])
        {
            nexthop_dereference(nexthop[i]);
            nexthop[i] = nullptr;   
            count++;
        }
    }
    return count;
}

nexthop_t *
nh_create_new_nexthop(c_string node_name, uint32_t oif_index, c_string gw_ip, uint16_t proto){

    nexthop_t *nexthop = new nexthop_t;
    nexthop->ifindex = oif_index; 
    string_copy((char *)nexthop->gw_ip, gw_ip, 16);
    if (node_name) {
        string_copy (nexthop->node_name , node_name, NODE_NAME_SIZE);
    }
    nexthop->ref_count = 0;
    nexthop->proto = proto;
    return nexthop;
}

bool 
nh_insert_new_nexthop_nh_array(
                       nexthop_t **nexthop_arry, 
                       nexthop_t *nxthop){

    int i = 0;

    for( ; i < MAX_NXT_HOPS; i++){
        if(nexthop_arry[i]) continue;
        nexthop_arry[i] = nxthop;
        nexthop_arry[i]->ref_count++;
        return true;
    }
    return false;
}

bool 
nh_remove_nexthop_from_nh_array (
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop) {

    int i = 0;
    
    for( ; i < MAX_NXT_HOPS; i++){
        
        if(!nexthop_array[i]) continue;
        if(nxthop_compare(nexthop_array[i], nxthop) == 0) {
            nexthop_dereference(nexthop_array[i]);
            nexthop_array[i] = nullptr;
            return true;
        }
    }
    return false;
}

bool
nh_is_nexthop_exist_in_nh_array(
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop){

    int i = 0;
    
    for( ; i < MAX_NXT_HOPS; i++){
        
        if (!nexthop_array[i]) continue;
        if (nxthop_compare (nexthop_array[i], nxthop) == 0) return true;
    }

    return false;
}

/*Copy all nexthops of src to dst, do not copy which are already
 * present*/
 int
nh_union_nexthops_arrays(nexthop_t **src, nexthop_t **dst){

    int i = 0;
    int j = 0;
    int copied_count = 0;

    while(j < MAX_NXT_HOPS && dst[j]){
        j++;
    }

    if(j == MAX_NXT_HOPS) return 0;

    for(; i < MAX_NXT_HOPS && j < MAX_NXT_HOPS; i++, j++){

        if(src[i] && nh_is_nexthop_exist_in_nh_array(dst, src[i]) == false){
            dst[j] = src[i];
            dst[j]->ref_count++;
            copied_count++;
        }
    }
    return copied_count;
}

c_string
nh_nexthops_str(nexthop_t **nexthops,  c_string buffer,  uint16_t buffer_size){

    memset(buffer, 0 , buffer_size);

    int i = 0, rc = 0;

    for( ; i < MAX_NXT_HOPS; i++){

        if(!nexthops[i]) continue;
        rc += snprintf(buffer + rc, buffer_size - rc, "%s ", nexthops[i]->node_name);
    }
    return buffer;
}

int8_t
nxthop_compare (nexthop_t *nh1, nexthop_t *nh2) {

    if (nh1->proto != nh2->proto) return -1;
    if (nh1->ifindex != nh2->ifindex) return -1;
    if (memcmp(&nh1->gw_ip, &nh2->gw_ip, 16) != 0) return -1;
    /* label_stack_compare returns true if equal, so negate it */
    if (!mpls_lstack_compare(nh1->lbls, nh2->lbls)) return -1;
    return 0;
}