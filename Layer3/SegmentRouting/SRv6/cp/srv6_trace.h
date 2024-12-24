#ifndef __SRV6_TRACER__
#define __SRV6_TRACER__

/* ISIS Trace Codes*/
#define TR_SRV6_IPC                    (1 << 0)
#define TR_SRV6_CONFIG            (1 << 1)
#define TR_SRV6_ROUTE             (1 << 2)
#define TR_SRV6_ALL                    (TR_SRV6_IPC  |\
                                                             TR_SRV6_CONFIG | \
                                                             TR_SRV6_ROUTE )


#endif 