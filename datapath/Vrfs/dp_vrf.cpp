#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../common/cmn_prefix.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "dp_vrf.h"
#include "../FIB/fib.h"
#include "../../EventDispatcher/event_dispatcher.h"
#include "../../net.h"
#include "../Layer2/arp/arp.h"
#include "../dp_uapi.h"

/* Hash function for vrf_id (uint8_t) keys */
static unsigned int 
vrf_id_hash_function(void *key) {
    uint8_t *vrf_id = (uint8_t *)key;
    /* Simple hash for 8-bit VRF ID */
    return (unsigned int)(*vrf_id);
}

/* Equality function for vrf_id keys */
static int 
vrf_id_key_equal_function(void *key1, void *key2) {
    uint8_t *vrf_id1 = (uint8_t *)key1;
    uint8_t *vrf_id2 = (uint8_t *)key2;
    return (*vrf_id1 == *vrf_id2);
}

void 
dp_init_vrf_hashtable (hashtable_t **ht) {

    /* Create hashtable with initial size of 8 entries (VRFs are typically few) */
    *ht = create_hashtable(8, vrf_id_hash_function, vrf_id_key_equal_function);
    
    if (!(*ht)) {
        /* Handle out of memory - could log error here */
        return;
    }
}

dp_vrf_t *
dp_look_up_vrf (hashtable_t *ht, uint8_t vrf_id) {
    if (!ht) {
        return NULL;
    }
    
    /* Search for the VRF using vrf_id as key */
    return (dp_vrf_t *)hashtable_search(ht, (void *)&vrf_id);
}

void
dp_insert_vrf (hashtable_t *ht, dp_vrf_t *vrf) {
    
    /* Allocate a key for the hashtable (hashtable takes ownership of key) */
    uint8_t *key = (uint8_t *)malloc(sizeof(uint8_t));

    *key = vrf->vrf_id;
    
    /* Insert the VRF with vrf_id as key */
    if (!hashtable_insert(ht, (void *)key, (void *)vrf)) {
        /* Insert failed - free the key we allocated */
        free(key);
    }
}

static void 
dp_destroy_vrf_cbk (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    dp_vrf_t *vrf = (dp_vrf_t *)arg;
    fib_destroy(vrf->fib_inet0);
    vrf->fib_inet0 = NULL;

    fib_destroy(vrf->fib_inet6);
    vrf->fib_inet6 = NULL;

    clear_arp_table(vrf->arp_table);
    XFREE(vrf->arp_table);

    free(vrf);
}

void dp_delete_vrf(dp_ctx_t *dp_ctx, hashtable_t *ht, uint8_t vrf_id)
{
    dp_vrf_t *vrf = (dp_vrf_t *)hashtable_remove(ht, (void *)&vrf_id);

    assert(vrf);

    task_create_new_job(EV_DP_PURGER(dp_ctx), (void *)vrf,
                dp_destroy_vrf_cbk, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_GARBAGE_COLLECTOR);

}

dp_vrf_t *
dp_create_vrf (hashtable_t *ht, char *vrf_name, uint8_t vrf_id) {
    
    /* Allocate new VRF structure */
    dp_vrf_t *vrf ;

    if ((vrf = dp_look_up_vrf (ht, vrf_id))) return vrf;

    vrf = (dp_vrf_t *)calloc(1, sizeof(dp_vrf_t));

    /* Initialize the VRF */
    vrf->vrf_id = vrf_id;
    
    /* Copy VRF name */
    if (vrf_name) {
        strncpy(vrf->vrf_name, vrf_name, sizeof(vrf->vrf_name) - 1);
        vrf->vrf_name[sizeof(vrf->vrf_name) - 1] = '\0';  /* Ensure null termination */
    } else {
        vrf->vrf_name[0] = '\0';
    }
    
    /* Initialize FIBs using FIB subsystem */
    vrf->fib_inet0 = fib_init(vrf, AF_IPV4, vrf_id);
    vrf->fib_inet6 = fib_init(vrf, AF_IPV6, vrf_id);
    vrf->fib_mpls0 = fib_init(vrf, AF_LABEL, vrf_id);

    init_arp_table (&vrf->arp_table);
    
    /* Insert into hashtable */
    dp_insert_vrf(ht, vrf);
    
    return vrf;
}

fib_t *
dp_look_up_fib_by_name (dp_ctx_t *dp_ctx, char *vrf_name, char *fib_name) {

    dp_vrf_t *vrf = NULL;

    struct hashtable_itr *itr = hashtable_iterator(dp_ctx->dp_vrf_ht);

    while (1)
    {
        vrf = (dp_vrf_t *)hashtable_iterator_value(itr);
        if (strcmp(vrf_name, vrf->vrf_name) == 0)
            break;
        if (!hashtable_iterator_advance(itr))
            break;
    }
    free(itr);

    if (!vrf) return NULL;

    if (strcmp (vrf->fib_inet0->name, fib_name) == 0) return vrf->fib_inet0;
    if (strcmp (vrf->fib_inet6->name, fib_name) == 0) return vrf->fib_inet6;
    if (strcmp (vrf->fib_mpls0->name, fib_name) == 0) return vrf->fib_mpls0;

    return NULL;
}
