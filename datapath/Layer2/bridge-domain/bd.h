#ifndef __DP_BD__
#define __DP_BD__

#include <stdint.h>

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct rte_mbuf;
typedef struct mac_table_ mac_table_t;
typedef struct mac_addr_ mac_addr_t;

int 
AC_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf);


int 
BD_SendPacketOut(
        dp_ctx_t *dp_ctx, 
        dp_intf_t *intf, 
        struct rte_mbuf *mbuf);

void 
bd_add_ac (dp_intf_t *bd_intf, dp_intf_t *ac);

dp_intf_t *
bd_ac_create (dp_ctx_t *dp_ctx, uint32_t ifindex );

void 
bd_del_ac (dp_intf_t *bd_intf, uint32_t ifindex);

bool 
bd_has_ac_member (dp_intf_t *bd_intf, uint32_t ac_ifindex);

void 
bd_ac_configure_8021q_tag (dp_intf_t *ac, uint16_t tag);

void 
bd_show (dp_intf_t *bd_intf) ;

void
bd_perform_mac_learning (dp_ctx_t *dp_ctx,
                         dp_intf_t *bd, 
                         mac_addr_t *src_mac, dp_intf_t *ac);

void 
bd_switch_forward_frame (dp_ctx_t *dp_ctx,
                         dp_intf_t *bd, 
                         dp_intf_t *recv_ac, 
                         mac_addr_t *dst_mac,
                         struct rte_mbuf *mbuf);

#endif 