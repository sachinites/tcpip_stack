#ifndef __RTM_GC__
#define __RTM_GC__

typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_ rtm_t;

#include "../libs/gluethread/glthread.h"

#pragma pack(push, 8)

typedef enum GC_TYPE_ {

    RTM_GC_RT,
    RTM_GC_NH
} GC_TYPE_T;

typedef struct rtm_gc_ {

    GC_TYPE_T gc_type;

    union {

        rtm_route *route;
        rtm_nh *nh;

    } u;

    rtm_t *rtm;

    glthread_t glue; 

} rtm_gc_t;

#pragma pack(pop)

GLTHREAD_TO_STRUCT(glue_to_gc, rtm_gc_t, glue);

void 
rtm_gc_route (rtm_t *rtm, rtm_route *route);

void 
rtm_gc_nh (rtm_t *rtm, rtm_nh *nh);

rtm_nh *
rtm_gc_lookup_nh (rtm_t *rtm, uint32_t nhidx);


#endif 