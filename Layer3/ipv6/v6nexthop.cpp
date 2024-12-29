#include <stdio.h>
#include <stdint.h>
#include "../../utils.h"
#include "../../tcp_public.h"
#include "v6nexthop.h"

void 
nexthop_init (v6nexthop_t *nexthop) {

    nexthop->hit_count = 0;
    nexthop->gw = {0};
    nexthop->oif = nullptr;
    nexthop->ifindex = 0;
    nexthop->ref_count = 0;
    nexthop->proto = 0;
    memset (&nexthop->u, 0, sizeof(nexthop->u));
}

int 
v6nh_flush_nexthops(v6nexthop_t **nexthop)
{

    int i = 0;
    int count = 0;

    if (!nexthop)
        return 0;

    for (; i < MAX_NXT_HOPS; i++)
    {

        if (nexthop[i])
        {
            assert(nexthop[i]->ref_count);
            nexthop[i]->ref_count--;
            if (nexthop[i]->ref_count == 0)
            {
                delete (nexthop[i]);
		        nexthop[i] = nullptr;
            }
            nexthop[i] = nullptr;
            count++;
        }
    }
    return count;
}

/* All fields of the the nexthops are keys 
    return -1 , if nxthops are completely different
    return 0, if nxthops are same
    return 1, if nxthops are to be replaced with one another
    nh1 - existing nexthop
    nh2 - new nexthop
*/
static int
v6_nexthop_compare (v6nexthop_t *nh1, v6nexthop_t *nh2) {

    if (nh1->proto != nh2->proto) return -1;
    if (nh1->ifindex == 0 && nh2->ifindex) return 1;
    if (nh1->ifindex != nh2->ifindex) return -1;
    if (memcmp(&nh1->gw, &nh2->gw, 16) != 0) return -1;
    if (nh1->metric != nh2->metric) return 1;

    switch (nh1->proto)
    {
        case PROTO_SRv6:
            if (nh1->u.srv6.endfn != nh2->u.srv6.endfn) return 1;
            if (nh1->u.srv6.flags != nh2->u.srv6.flags) return 1;
            if ((!nh1->u.srv6.segment_lst && nh2->u.srv6.segment_lst) || 
                    (nh1->u.srv6.segment_lst && !nh2->u.srv6.segment_lst)) return 1;
            if (nh1->u.srv6.n_segment_list != nh2->u.srv6.n_segment_list) return 1;
            for (int i = 0; i < nh1->u.srv6.n_segment_list; i++) {
                if (memcmp (nh1->u.srv6.segment_lst[i].addr, 
                                      nh2->u.srv6.segment_lst[i].addr, 
                                      sizeof (nh1->u.srv6.segment_lst[i].addr))) {
                    return 1;
                }
            }
            break;
        default:
            break;
    }
    
    return 0;
}

bool 
v6nh_insert_new_nexthop_nh_array(
                       v6nexthop_t **nexthop_arry, 
                       v6nexthop_t *nxthop){

    int i = 0;

    for( ; i < MAX_NXT_HOPS; i++){
        if(nexthop_arry[i]) continue;
        nexthop_arry[i] = nxthop;
        nexthop_arry[i]->ref_count++;
        return true;
    }
    return false;
}

int
v6nh_is_nexthop_exist_in_nh_array(
                        v6nexthop_t **nexthop_array, 
                        v6nexthop_t *nxthop, int *index){

    int i = 0, rc;

    for( ; i < MAX_NXT_HOPS; i++){
        
        if (!nexthop_array[i]) continue;
         rc = v6_nexthop_compare(nexthop_array[i], nxthop);
         if (rc == -1) continue;
         if (index) *index = i;
         return rc;
    }

    if (index) *index = -1;
    return -1;
}

/*Copy all nexthops of src to dst, do not copy which are already
 * present*/
 int
v6nh_union_nexthops_arrays(v6nexthop_t **src, v6nexthop_t **dst){

    int i = 0;
    int j = 0;
    int copied_count = 0;

    while(j < MAX_NXT_HOPS && dst[j]){
        j++;
    }

    if(j == MAX_NXT_HOPS) return 0;

    for(; i < MAX_NXT_HOPS && j < MAX_NXT_HOPS; i++, j++){

        if(src[i] && v6nh_is_nexthop_exist_in_nh_array(dst, src[i], 0) == -1){
            dst[j] = src[i];
            dst[j]->ref_count++;
            copied_count++;
        }
    }
    return copied_count;
}


v6nexthop_t *
v6nexthop_find (v6nexthop_t **nexthops, 
                            ipv6_addr_t *gw, 
                            uint32_t ifindex, 
                            uint16_t proto, 
                            int *index) {

    int i = 0;
    for( ; i < MAX_NXT_HOPS; i++){
        
        if (!nexthops[i])
            continue;

        if (nexthops[i]->ifindex == ifindex && 
                (memcmp(&nexthops[i]->gw, gw, 16) == 0) &&
                nexthops[i]->proto == proto )
        {
            if (index) *index = i;
            return nexthops[i];
        }
    }

    return NULL;
}