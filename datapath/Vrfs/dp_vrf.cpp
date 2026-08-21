#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rte_hash.h>
#include "dp_vrf.h"
#include "../FIB/fib.h"
#include "../../libs/EventDispatcher/event_dispatcher.h"
#include "../../net.h"
#include "../Layer2/arp/arp.h"
#include "../dp_uapi.h"
#include "../dp_ctx.h"

void
dp_init_vrf_table (dp_ctx_t *dp_ctx)
{
    memset(dp_ctx->dp_vrf_table, 0, sizeof(dp_ctx->dp_vrf_table));
}

dp_vrf_t *
dp_look_up_vrf (dp_ctx_t *dp_ctx, int16_t vrf_id)
{
    if (!dp_ctx || vrf_id < 0 || vrf_id >= DP_MAX_VRF)
        return NULL;
    return dp_ctx->dp_vrf_table[vrf_id];
}

void
dp_insert_vrf (dp_ctx_t *dp_ctx, dp_vrf_t *vrf)
{
    assert(dp_ctx && vrf);
    assert(vrf->vrf_id < DP_MAX_VRF);
    assert(!dp_ctx->dp_vrf_table[vrf->vrf_id]);
    dp_ctx->dp_vrf_table[vrf->vrf_id] = vrf;
}

static void
dp_destroy_vrf_cbk (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    dp_vrf_t *vrf = (dp_vrf_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    (void)arg_size;

    fib_destroy(vrf->fib_inet0);
    vrf->fib_inet0 = NULL;

    fib_destroy(vrf->fib_inet6);
    vrf->fib_inet6 = NULL;

    clear_arp_table(dp_ctx, vrf->arp_table);
    if (vrf->arp_table->hash) {
        rte_hash_free(vrf->arp_table->hash);
        vrf->arp_table->hash = NULL;
    }
    XFREE(vrf->arp_table);

    free(vrf);
}

void
dp_delete_vrf(dp_ctx_t *dp_ctx, uint8_t vrf_id)
{
    dp_vrf_t *vrf;

    assert(dp_ctx);
    assert(vrf_id < DP_MAX_VRF);

    vrf = dp_ctx->dp_vrf_table[vrf_id];
    assert(vrf);

    dp_ctx->dp_vrf_table[vrf_id] = NULL;

    task_create_new_job(EV_DP_PURGER(dp_ctx), (void *)vrf,
                dp_destroy_vrf_cbk,
                TASK_ONE_SHOT,
                TASK_PRIORITY_GARBAGE_COLLECTOR);
}

dp_vrf_t *
dp_create_vrf (dp_ctx_t *dp_ctx, const char *ctx_name, char *vrf_name, uint8_t vrf_id)
{
    dp_vrf_t *vrf;

    assert(dp_ctx);
    assert(vrf_id < DP_MAX_VRF);

    if ((vrf = dp_look_up_vrf(dp_ctx, vrf_id)))
        return vrf;

    vrf = (dp_vrf_t *)calloc(1, sizeof(dp_vrf_t));

    vrf->vrf_id = vrf_id;

    if (vrf_name) {
        strncpy(vrf->vrf_name, vrf_name, sizeof(vrf->vrf_name) - 1);
        vrf->vrf_name[sizeof(vrf->vrf_name) - 1] = '\0';
    } else {
        vrf->vrf_name[0] = '\0';
    }

    vrf->fib_inet0 = fib_init(vrf, AF_IPV4, vrf_id);
    vrf->fib_inet6 = fib_init(vrf, AF_IPV6, vrf_id);
    vrf->fib_mpls0 = fib_init(vrf, AF_LABEL, vrf_id);

    init_arp_table (&vrf->arp_table, ctx_name, vrf->vrf_name);

    dp_insert_vrf(dp_ctx, vrf);

    return vrf;
}

fib_t *
dp_look_up_fib_by_name (dp_ctx_t *dp_ctx, char *vrf_name, char *fib_name)
{
    int i;
    dp_vrf_t *vrf = NULL;

    if (!dp_ctx || !vrf_name || !fib_name)
        return NULL;

    for (i = 0; i < DP_MAX_VRF; i++) {
        dp_vrf_t *v = dp_ctx->dp_vrf_table[i];
        if (v && strcmp(vrf_name, v->vrf_name) == 0) {
            vrf = v;
            break;
        }
    }

    if (!vrf)
        return NULL;

    if (strcmp (vrf->fib_inet0->name, fib_name) == 0) return vrf->fib_inet0;
    if (strcmp (vrf->fib_inet6->name, fib_name) == 0) return vrf->fib_inet6;
    if (strcmp (vrf->fib_mpls0->name, fib_name) == 0) return vrf->fib_mpls0;

    return NULL;
}

arp_table_t *
dp_vrf_get_arp_cache (dp_ctx_t *dp_ctx, char *vrf_name)
{
    int i;

    if (!dp_ctx || !vrf_name)
        return NULL;

    for (i = 0; i < DP_MAX_VRF; i++) {
        dp_vrf_t *vrf = dp_ctx->dp_vrf_table[i];
        if (vrf && strcmp(vrf_name, vrf->vrf_name) == 0)
            return vrf->arp_table;
    }

    return NULL;
}
