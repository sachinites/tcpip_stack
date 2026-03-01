
#include <stdint.h>
#include "dp_uapi.h"
#include "dp_ctx.h"
#include "Interface/dp_intf_store.h"

dp_intf_t *
dp_uapi_look_up_interface (dp_ctx_t *dp_ctx, uint32_t port_id) {

    return dp_look_up_interface (dp_ctx->dp_intf_ht, port_id);
}

