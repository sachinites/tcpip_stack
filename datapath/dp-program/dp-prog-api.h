
#ifndef __DP_PROG_API__
#define __DP_PROG_API__

typedef struct dp_msg_ dp_msg_t;
typedef struct dp_ctx_ dp_ctx_t;

dp_msg_t *
cp2dp_msg_alloc ();

void
cp2dp_msg_free (dp_msg_t *dp_msg);

void
dp_mac_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg);

void
np_recv_cp_pkt_block (dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) ;

void
dp_fib_table_process_msg (dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) ;

void
dp_vrf_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) ;

void
dp_intf_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg);

void
dp_generic_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg);

#endif 