#ifndef __ISIS_STRUCT__
#define __ISIS_STRUCT__

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t pn_id_t;

#pragma pack (push,1)

typedef struct isis_system_id_ {

    uint32_t rtr_id;
    uint8_t pn_id;
} isis_system_id_t;

typedef struct isis_lan_id_ {

    uint32_t rtr_id;
    uint8_t pn_id;
}isis_lan_id_t;

typedef struct isis_lsp_id_ {

    isis_system_id_t sys_id;
    uint8_t fragment;
    uint16_t unused; // Obey RFC, make LSP 8B long
}isis_lsp_id_t;

typedef enum ISIS_LVL_ {

    isis_level_1,
    isis_level_2,
    isis_level_12
} ISIS_LVL;
#pragma pack(pop)

static bool
isis_is_lan_id_null (isis_lan_id_t lan_id) {

    return (!lan_id.pn_id && !lan_id.rtr_id);
}

#endif
