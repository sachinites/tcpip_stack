#ifndef __BITMAP__
#define __BITMAP__

#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

typedef enum {
	ZERO,
	ONE,
	DONT_CARE,
	BIT_TYPE_MAX
} bit_type_t;

typedef struct bitmap_ {

    uint32_t *bits;
    uint16_t tsize;
    uint16_t next;
} bitmap_t;

void bitmap_init(bitmap_t *bitmap, uint16_t size) ;
void bitmap_free_internal(bitmap_t *bitmap);
void bitmap_free(bitmap_t *bitmap);
void bitmap_reset(bitmap_t *bitmap);
bool bitmap_at(bitmap_t *bitmap, uint16_t index);
bit_type_t bitmap_effective_bit_at(bitmap_t *prefix, bitmap_t *mask, uint16_t pos);
void bitmap_set_bit_at(bitmap_t *bitmap, uint16_t index) ;
void bitmap_unset_bit_at(bitmap_t *bitmap, uint16_t index) ;
void bitmap_inverse(bitmap_t *bitmap, uint16_t count);

void
bitmap_slow_copy(bitmap_t *src, 
                      bitmap_t *dst,
                      uint16_t src_start_offset,
                      uint16_t dst_start_offset,
                      uint16_t count);

bool
bitmap_slow_compare(bitmap_t *src, 
                      bitmap_t *dst,
                      uint16_t src_start_offset,
                      uint16_t dst_start_offset,
                      uint16_t count);

bool
bitmap_fast_compare(bitmap_t *src, 
                              bitmap_t *dst,
                              uint16_t count);

void
bitmap_fast_copy(bitmap_t *src, 
                              bitmap_t *dst,
                              uint16_t count);

bool 
bitmap_prefix_match(bitmap_t *input, 
                                    bitmap_t *prefix, 
                                    bitmap_t *mask,
                                    uint16_t prefix_len);

void
bitmap_prefix_apply_mask(bitmap_t *prefix, bitmap_t *mask, uint16_t count) ;

void bitmap_lshift(bitmap_t *bitmap, uint16_t count); 
void bitmap_rshift(bitmap_t *bitmap, uint16_t count);
void bitmap_print(bitmap_t *bitmap); 
void bitmap_set(bitmap_t *bitmap, uint16_t start_offset, uint16_t end_offset, bool set);
void bitmap_prefix_print(bitmap_t *prefix, bitmap_t *mask, uint16_t count);

#define ITERATE_BITMAP_BEGIN(bitmap_ptr, start_index, _index, boolout) \
    { \
    int _i; \
    for (_i = start_index; _i < bitmap_ptr->tsize ; _i++) { \
    boolout = bitmap_at(bitmap_ptr, _i) ? true : false; \
    _index = _i;

#define  ITERATE_BITMAP_END }}

#define ITERATE_MASKED_BITMAP_BEGIN(prefix, mask, prefix_len, index, bit) \
{														  		    \
	int _i;									             	      \
	for (_i = 0, index = 0; _i < prefix_len;    \
			_i++, index = _i) {	  					     \
		if (bitmap_at(mask, _i)) {				 	 \
			bit = DONT_CARE;			  		   \
		}											   		  	   \
		else if (bitmap_at(prefix, _i)) {	   		\
			bit = ONE;								     \
		}												        \
		else {												  \
			bit = ZERO;							  		\
		}

#define ITERATE_MASKED_BITMAP_END }}

/* Functions on 32 bit integers, used by bit arrays as helper fns */
bool
prefix32bit_match(uint32_t input, uint32_t prefix, uint32_t mask, uint8_t prefix_len);

void
uint32_bits_copy(uint32_t *src, uint32_t *dst,
                             uint8_t src_start_pos,
                             uint8_t dst_start_pos, uint8_t count);

void
uint32_bits_copy_preserve(uint32_t *src, uint32_t *dst, 
                                            uint8_t src_start_pos, uint8_t dst_start_pos,
                                            uint8_t count);

bool
uint32_bits_compare  (uint32_t bits1, uint32_t bits2, uint8_t count);

uint32_t
bits_generate_ones(uint8_t start_offset, uint8_t end_offset);

static inline uint32_t 
LSHIFT (uint32_t N, uint16_t n) {
 
    if (n != 32) return ((N << n));
    else return (0);
}

static inline uint32_t 
RSHIFT (uint32_t N, uint16_t n) {
 
    if (n != 32) return ((N >> n)); 
    else return (0);
}

#endif 