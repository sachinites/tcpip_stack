#ifndef __ISIS_UTILS__
#define __ISIS_UTILS__

#include <stdbool.h>
#include "../../utils.h"

typedef struct isis_lan_id_ isis_lan_id_t;
typedef struct isis_lsp_id_ isis_lsp_id_t;
typedef struct isis_system_id_ isis_system_id_t;

const c_string
isis_lan_id_tostring (isis_lan_id_t *sys_id, const c_string buffer);

int
isis_lan_id_compare (isis_lan_id_t *sys_id1,
                                          isis_lan_id_t *sys_id2);

const c_string
isis_lsp_id_tostring (isis_lsp_id_t *lsp_id, const c_string buffer);

int
isis_lsp_id_compare (isis_lsp_id_t *lsp_id1,
                                    isis_lsp_id_t *lsp_id2);

const c_string
isis_system_id_tostring (isis_system_id_t *sys_id, const c_string buffer);

int
isis_system_id_compare (isis_system_id_t *sys_id1,
                                         isis_system_id_t *sys_id2);

void
isis_show_traceoptions (node_t *node) ;

#endif