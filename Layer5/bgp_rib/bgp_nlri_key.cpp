#include <stdlib.h>
#include <string.h>

#include "bgp_nlri_key.h"

bgp_nlri_key_t *
bgp_nlri_key_dup(const bgp_nlri_key_t *key)
{
    bgp_nlri_key_t *copy;

    if (!key || key->wire_len == 0 || key->wire_len > BGP_NLRI_WIRE_MAX) {
        return NULL;
    }

    copy = (bgp_nlri_key_t *)calloc(1, sizeof(*copy));
    if (!copy) {
        return NULL;
    }

    copy->wire_len = key->wire_len;
    memcpy(copy->wire, key->wire, key->wire_len);
    return copy;
}

void
bgp_nlri_key_free(bgp_nlri_key_t *key)
{
    free(key);
}

int
bgp_nlri_key_cmp(const bgp_nlri_key_t *a, const bgp_nlri_key_t *b)
{
    if (!a && !b) {
        return 0;
    }
    if (!a) {
        return -1;
    }
    if (!b) {
        return 1;
    }
    if (a->wire_len != b->wire_len) {
        return (a->wire_len < b->wire_len) ? -1 : 1;
    }
    return memcmp(a->wire, b->wire, a->wire_len);
}

unsigned int
bgp_nlri_key_hash(const bgp_nlri_key_t *key)
{
    unsigned int hash = 5381;
    uint16_t i;

    if (!key) {
        return 0;
    }

    for (i = 0; i < key->wire_len; i++) {
        hash = ((hash << 5) + hash) + key->wire[i];
    }

    return hash;
}

unsigned int
bgp_nlri_key_hash_fn(void *key)
{
    return bgp_nlri_key_hash((const bgp_nlri_key_t *)key);
}

int
bgp_nlri_key_equal_fn(void *key1, void *key2)
{
    const bgp_nlri_key_t *a = (const bgp_nlri_key_t *)key1;
    const bgp_nlri_key_t *b = (const bgp_nlri_key_t *)key2;

    if (!a || !b) {
        return 0;
    }

    if (a->wire_len != b->wire_len) {
        return 0;
    }

    return memcmp(a->wire, b->wire, a->wire_len) == 0;
}

uint16_t
bgp_nlri_key_bit_length(const bgp_nlri_key_t *key)
{
    if (!key) {
        return 0;
    }

    return (uint16_t)(key->wire_len * 8);
}
