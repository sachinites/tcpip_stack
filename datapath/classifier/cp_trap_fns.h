#ifndef __CP_TRAP_FNS__
#define __CP_TRAP_FNS__

struct rte_mbuf;

void isis_trap_app_cbk(void *cp_ctx, struct rte_mbuf *mbuf);

#endif /* __CP_TRAP_FNS__ */