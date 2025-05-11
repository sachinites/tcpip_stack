#ifndef __A_B__
#define __A_B__

#include <stdint.h>
#include <stdbool.h>

typedef struct ABmgr_  ABmgr_t;
typedef struct circular_buffer_t *cbuffer;

extern ABmgr_t *ABmgr_get_instance (uint16_t A, uint16_t B) ;
extern bool ABmgr_insert_string (ABmgr_t *abmgr, char *string, uint16_t msg_len, bool match, bool calloc_str);
extern void ABmgr_reset(ABmgr_t *abmgr);
extern void ABmgr_print (ABmgr_t *abmgr, void (*printfn)(unsigned char*, int)) ;
extern void ABmgr_destroy(ABmgr_t *abmgr) ;
extern bool ABmgr_is_printable (ABmgr_t *abmgr) ;
extern uint32_t ABmgr_data_copy (ABmgr_t *abmgr,  char *buffer,  uint32_t bsize) ;

void circular_buffer_reset (circular_buffer_t *cbuffer) ;
void circular_buffer_insert (circular_buffer_t *cbuffer, void *data, uint16_t data_len) ;
void *circular_buffer_tail_remove (circular_buffer_t *cbuffer, uint16_t *data_len) ;
void circular_buffer_destroy (circular_buffer_t *cbuffer);

#endif 