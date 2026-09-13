#ifndef BGP_NLRI_KEY_H_
#define BGP_NLRI_KEY_H_

#include "bgp_rib_types.h"

bgp_nlri_key_t *
bgp_nlri_key_dup(const bgp_nlri_key_t *key);

void
bgp_nlri_key_free(bgp_nlri_key_t *key);

int
bgp_nlri_key_cmp(const bgp_nlri_key_t *a, const bgp_nlri_key_t *b);

unsigned int
bgp_nlri_key_hash(const bgp_nlri_key_t *key);

unsigned int
bgp_nlri_key_hash_fn(void *key);

int
bgp_nlri_key_equal_fn(void *key1, void *key2);

uint16_t
bgp_nlri_key_bit_length(const bgp_nlri_key_t *key);

#endif /* BGP_NLRI_KEY_H_ */
