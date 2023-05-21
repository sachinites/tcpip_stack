#include <stdio.h>
#include <stdint.h>
#include "../../utils.h"
#include "../../tcp_public.h"

int
nh_flush_nexthops(nexthop_t **nexthop){

    int i = 0;
    int count = 0;

    if(!nexthop) return 0;

    for( ; i < MAX_NXT_HOPS; i++){

        if(nexthop[i]){
            assert(nexthop[i]->ref_count);
            nexthop[i]->ref_count--;
            if(nexthop[i]->ref_count == 0){
                XFREE(nexthop[i]);
            }
            nexthop[i] = NULL;
            count++;
        }
    }
    return count;
}

nexthop_t *
nh_create_new_nexthop(c_string node_name, uint32_t oif_index, c_string gw_ip, uint8_t proto){

    nexthop_t *nexthop = ( nexthop_t *)XCALLOC(0, 1, nexthop_t);
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
nh_is_nexthop_exist_in_nh_array(
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop){

    int i = 0;
    for( ; i < MAX_NXT_HOPS; i++){
        
        if (!nexthop_array[i])
            continue;

        if (nexthop_array[i]->oif == nxthop->oif)
            return true;
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
