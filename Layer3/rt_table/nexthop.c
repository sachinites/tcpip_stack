#include <stdio.h>
#include <stdint.h>
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
nh_create_new_nexthop(uint32_t oif_index, char *gw_ip, uint8_t proto){

    nexthop_t *nexthop = XCALLOC(0, 1, nexthop_t);
    nexthop->ifindex = oif_index;
    strncpy(nexthop->gw_ip, gw_ip, 16);
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

char *
nh_nexthops_str(nexthop_t **nexthops){

    static char buffer[256];
    memset(buffer, 0 , 256);

    int i = 0;

    for( ; i < MAX_NXT_HOPS; i++){

        if(!nexthops[i]) continue;
        snprintf(buffer, 256, "%s ", nexthop_node_name(nexthops[i]));
    }
    return buffer;
}