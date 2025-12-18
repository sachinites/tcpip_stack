#ifndef __FIB_NH__
#define __FIB_NH__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../RTM/rtm_fib_common.h"
#include "../common/mpls_lstack.h"

typedef struct fib_ fib_t;
typedef struct fib_nh_ fib_nh_t;


#pragma pack(push, 8)

typedef struct fib_nh_fwd_info_ {

    InterfaceP oif;
    cmn_prefix_t nh_addr;
    uint16_t fwd_flags;

    union {
        
        /*MPLS  Label Stack*/
        struct {
            mpls_lstack_t label_stack;
        } mpls_fwd;

        /*SRv6 Stack*/
        struct {    
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            uint8_t v6segment_lst[MAX_LBL_DEPTH][16];
        } v6_fwd;

    }u;

    ~fib_nh_fwd_info_() {
        oif = nullptr;
    }

} fib_nh_fwd_info_t;

typedef struct fib_nh_ {

    fib_nh_fwd_info_t *fwd_info;
    avltree_node_t idx_glue;
    uint32_t hit_count;
    uint32_t ref_count;

} fib_nh_t;

#pragma pack(pop)

void fib_nh_reference (fib_nh_t *nh);
void fib_nh_dereference (fib_t *fib, fib_nh_t *nh);
fib_nh_t* fib_nh_create (fib_t *fib, fib_nh_t *nh_template);
void fib_register_nh(fib_t *fib, fib_nh_t *nh);
fib_nh_t* fib_nh_lookup (fib_t *fib, fib_nh_t *nh_template);

#endif 