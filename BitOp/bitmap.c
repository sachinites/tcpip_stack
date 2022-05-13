#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include "bitmap.h"

void bitmap_init(bitmap_t *bitmap, uint16_t size) {

    assert(!(size % 32));
    bitmap->bits = (uint32_t *)calloc(size/8, sizeof(uint8_t));
    bitmap->tsize = size;
    bitmap->next = 0;
}

void bitmap_free_internal(bitmap_t *bitmap) {
    free(bitmap->bits);
}

void bitmap_free(bitmap_t *bitmap) {
   bitmap_free_internal(bitmap);
   free(bitmap);
}

void bitmap_reset(bitmap_t *bitmap) {
    bitmap->next = 0;
    memset(bitmap->bits, 0, bitmap->tsize / 8);
}

bool bitmap_at(bitmap_t *bitmap, uint16_t index) {

    uint16_t n_blocks = index / 32;
    uint8_t bit_pos = index % 32;
    uint32_t *ptr = (uint32_t *)bitmap->bits + n_blocks;
    return htonl(*ptr) & (1 << (32 - bit_pos - 1));   
}

/* Endianess independent */
void
bitmap_set_bit_at(bitmap_t *bitmap, uint16_t index) {

    uint16_t n_blocks = index / 8;
    uint8_t bit_pos = index % 8;
    uint8_t *ptr = (uint8_t *)bitmap->bits + n_blocks;
    *ptr |=  (1 << (8 - bit_pos - 1));   
}

/* Endianess independent */
void
bitmap_unset_bit_at(bitmap_t *bitmap, uint16_t index) {

    uint16_t n_blocks = index / 8;
    uint8_t bit_pos = index % 8;
    uint8_t *ptr = (uint8_t *)bitmap->bits + n_blocks;
    *ptr &=  (~(1 << (8 - bit_pos - 1)));   
}

void 
bitmap_set(bitmap_t *bitmap, uint16_t start_offset, 
                            uint16_t end_offset, bool set) {
    
}

void
bitmap_prefix_apply_mask(bitmap_t *prefix, bitmap_t *mask, uint16_t count) {

    int n_blocks = count / 32;
    int rem_bits = count % 32;

    if (rem_bits) {
        n_blocks++;
    }

    int i;
    for (i = 0; i < n_blocks - 1; i++) {
        *(prefix->bits + i) &= *(mask->bits + i);
    }

    if (!rem_bits) {
        *(prefix->bits + i) &= *(mask->bits + i);
        return;
    }

    uint32_t temp = bits_generate_ones(0, rem_bits - 1);
    temp = ~temp;
    uint32_t mask2 = htonl(*(mask->bits + i));
    mask2 |= temp;
    *(prefix->bits + i) = htonl(htonl(*(prefix->bits + i)) & mask2);
}

void
bitmap_inverse(bitmap_t *bitmap, uint16_t count) {

    int n_blocks = count / 32;
    int rem_bits = count % 32;

    if (rem_bits) {
        n_blocks++;
    }

    int i;
    for (i = 0; i < n_blocks - 1; i++) {
        *(bitmap->bits + i) = ~(*(bitmap->bits + i));
    }

    if (!rem_bits) {
        *(bitmap->bits + i) = ~(*(bitmap->bits + i));
            return ;
    }

    uint32_t temp = bits_generate_ones(0, rem_bits - 1);
    *(bitmap->bits + i) = htonl(htonl(*(bitmap->bits + i)) ^ temp);
}

void
bitmap_slow_copy(bitmap_t *src, 
                      bitmap_t *dst,
                      uint16_t src_start_offset,
                      uint16_t dst_start_offset,
                      uint16_t count) {

    bool bit;
    uint16_t index;
    ITERATE_BITMAP_BEGIN(src,  src_start_offset, index, bit) {

        if (bit) {
            bitmap_set_bit_at(dst, dst_start_offset);
        }
        else {
            bitmap_unset_bit_at(dst, dst_start_offset);
        }
        dst_start_offset++;
        count--;
        if (count == 0) {
            return;
        }
    } ITERATE_BITMAP_END;
}

void
bitmap_fast_copy(bitmap_t *src, 
                              bitmap_t *dst,
                              uint16_t count) {

    int n_blocks = count / 32;
    int rem_bits = count % 32;

    if (rem_bits) {
        n_blocks++;
    }

    int i;
    for (i = 0; i < n_blocks - 1; i++) {    
        *(dst->bits + i) = *(src->bits + i);
    }

    if (!rem_bits) {
        *(dst->bits + i) = *(src->bits + i);
        return;
    }

    uint32_bits_copy(src->bits + i, dst->bits + i, 0, 0, rem_bits);
}

static void
bitmap_lshift32(bitmap_t *bitmap, uint16_t count) {

    int i;
    uint16_t n_blocks = bitmap->tsize / 32;
    uint32_t *ptr = bitmap->bits;
    uint32_t mask= 0, temp;

    assert(count <= 32);
    
    *ptr = htonl(LSHIFT(htonl(*ptr), count));
    mask = bits_generate_ones(0, count - 1);

    for (i = 1; i < n_blocks; i++) {
        
        temp = htonl(*(ptr + i)) & mask;
        temp = RSHIFT(temp, 32 - count);
        *(ptr + i -1) = htonl(htonl(*(ptr + i -1)) |  temp);
        *(ptr + i) = htonl(LSHIFT(htonl(*(ptr + i)), count));
    }
}

void
bitmap_lshift(bitmap_t *bitmap, uint16_t count) {

    int N = count / 32;
    int i;
    for (i = 0; i < N; i++) {
        bitmap_lshift32(bitmap, 32);
    }
    N = count % 32;
    if (N == 0) return;
    bitmap_lshift32(bitmap, N);
}

static void
bitmap_rshift32(bitmap_t *bitmap, uint16_t count) {
    
    int i;
    uint16_t n_blocks = bitmap->tsize / 32;
    uint32_t *ptr = (uint32_t *)bitmap->bits ;
    uint32_t mask= 0, temp;

    assert(count <= 32);
    
    *(ptr + n_blocks -1)  = htonl(RSHIFT(htonl(*(ptr + n_blocks -1)), count));
    mask = bits_generate_ones(32 - count, 31);

    for (i = n_blocks - 2; i >= 0; i--) {
        
        temp = htonl(*(ptr + i)) & mask;
        temp = LSHIFT(temp, 32 - count);
         *(ptr + i +1) = htonl(htonl(*(ptr + i +1)) |  temp);
        *(ptr + i) = htonl(RSHIFT(htonl(*(ptr + i)), count));
    }
}

void
bitmap_rshift(bitmap_t *bitmap, uint16_t count) {

    int N = count / 32;
    int i;
    for (i = 0; i < N; i++) {
        bitmap_rshift32(bitmap, 32);
    }
    N = count % 32;
    if (N == 0) return;
    bitmap_rshift32(bitmap, N);
}

bool
bitmap_slow_compare(bitmap_t *src, 
                      bitmap_t *dst,
                      uint16_t src_start_offset,
                      uint16_t dst_start_offset,
                      uint16_t count) {

    uint16_t index;
    bool bit;

    ITERATE_BITMAP_BEGIN(src, src_start_offset, index, bit) {

        if (bitmap_at(dst, dst_start_offset) == bit) {
            dst_start_offset++;
            count--;
            if (count == 0) return true;
            continue;
        }
        return false;
    } ITERATE_BITMAP_END;
    return true;
}

bool
bitmap_fast_compare(bitmap_t *src, 
                                    bitmap_t *dst,
                                    uint16_t count) {

    int n_blocks = count / 32;
    int rem_bits = count % 32;

    if (rem_bits) {
        n_blocks++;
    }

    int i;
    for (i = 0; i < n_blocks - 1; i++) {
        if (*(dst->bits + i) == *(src->bits + i)) {
            continue;
        }
        return false;
    }

    if (!rem_bits) {
        if (*(dst->bits + i) == *(src->bits + i)) {
            return true;
        }
        return false;
    }

    return uint32_bits_compare(htonl(*(src->bits + i)) , htonl(*(dst->bits + i)), rem_bits);
}

bool 
bitmap_prefix_match(bitmap_t *input, 
                                    bitmap_t *prefix, 
                                    bitmap_t *mask,
                                    uint16_t prefix_len) {

    int n_blocks = prefix_len / 32;
    int rem_bits = prefix_len % 32;
    if (rem_bits) n_blocks++;

    int i;

    for (i = 0; i < n_blocks - 1; i++) {
        if (!prefix32bit_match (htonl(*(input->bits + i)),
                                             htonl(*(prefix->bits + i)),  
                                             htonl(*(mask->bits + i)), 32)) {
            return false;
        }
    }

    return prefix32bit_match (htonl(*(input->bits + i)), 
                                              htonl(*(prefix->bits + i)), 
                                              htonl(*(mask->bits + i)), 
                                              !rem_bits ? 32 :  rem_bits);
}

bit_type_t 
bitmap_effective_bit_at(bitmap_t *prefix, bitmap_t *mask, uint16_t pos) {

     if (bitmap_at(mask, pos)) {
            return DONT_CARE;
        }
        else if (bitmap_at(prefix, pos)) {
            return ONE;
        }
        else {
            return ZERO;
        }
}

void
bitmap_print(bitmap_t *bitmap) {

    uint16_t index;
    bool bit;

    ITERATE_BITMAP_BEGIN(bitmap, 0, index, bit) {

        //printf ("[%d %d]\n", index, bit ? 1 : 0);
        #if 0
        if (index % 16 == 0) {
            printf (" ");
        }
        #endif
        printf("%d", bit ? 1 : 0);
    }ITERATE_BITMAP_END;
    printf("\n");
}

void
bitmap_prefix_print(bitmap_t *prefix, bitmap_t *mask, uint16_t count) {

    bit_type_t bit;
    uint16_t index;

    ITERATE_MASKED_BITMAP_BEGIN(prefix, mask, count, index, bit) {

        switch(bit) {
            case DONT_CARE:
                printf ("X");
                break;
            case ONE:
                printf ("1");
                break;
            case ZERO:
                printf("0");
            default: ;
        }
    }ITERATE_MASKED_BITMAP_END;
}

/* Functions on 32 bit integers, used by bitmaps as helper fns */

bool
prefix32bit_match(uint32_t input, uint32_t prefix, 
                                uint32_t mask, uint8_t prefix_len) {

	if (!prefix_len) return true;

	uint32_t unwanted_bits = ~0;
	unwanted_bits = RSHIFT(unwanted_bits , 32 - prefix_len);
    unwanted_bits = LSHIFT(unwanted_bits , 32 - prefix_len);

	if ((input & (~mask) & unwanted_bits) == (prefix & (~mask) & unwanted_bits)) {
		return true;
	}
	return false;
}

void
uint32_bits_copy(uint32_t *src, uint32_t *dst,
                             uint8_t src_start_pos,
                             uint8_t dst_start_pos, uint8_t count) {

    *dst = 0;
    *dst = *src;
    *dst = (*dst) << src_start_pos;
	*dst = (*dst) >> dst_start_pos;
    *dst = *dst >> (32 - count - dst_start_pos );
    *dst = *dst << (32 - count - dst_start_pos );
    *dst = *dst;
}

void
uint32_bits_copy_preserve(uint32_t *src, 
                                            uint32_t *dst, 
                                            uint8_t src_start_pos,
                                            uint8_t dst_start_pos,
                                            uint8_t count) {

	uint32_t dst_old_mask = 
        bits_generate_ones(dst_start_pos, dst_start_pos + count - 1);
	dst_old_mask = ~dst_old_mask;
	uint32_t old_dst = htonl(*dst) & dst_old_mask;
	uint32_bits_copy(src, dst, src_start_pos, dst_start_pos, count);
	*dst = htonl(htonl(*dst) | old_dst);
}

bool
uint32_bits_compare (uint32_t bits1, uint32_t bits2, uint8_t count) {

	uint32_t unwanted_bits = bits_generate_ones(0, count - 1);
	return ((bits1 & unwanted_bits) == (bits2 & unwanted_bits));
}

uint32_t
bits_generate_ones(uint8_t start_offset, uint8_t end_offset) {

	if (start_offset > 31 || end_offset > 31) assert(0);
	assert(start_offset <= end_offset);

	uint32_t temp = ~0;
	temp = temp << start_offset;
	temp = temp >> start_offset;
	temp = temp >> (32 - end_offset -1);
	temp = temp << (32 - end_offset -1);
	return temp;
}

#if 0
int
main(int argc, char **argv) {

    bitmap_t bm;
     bitmap_init(&bm, 64);
    bitmap_set_bit_at(&bm, 0);
    bitmap_set_bit_at(&bm, 1);
    bitmap_set_bit_at(&bm, 2);
    bitmap_set_bit_at(&bm, 3);
    bitmap_set_bit_at(&bm, 11);
    bitmap_set_bit_at(&bm, 12);
    bitmap_set_bit_at(&bm, 25);
    bitmap_set_bit_at(&bm, 26);
    bitmap_set_bit_at(&bm, 27);
    bitmap_set_bit_at(&bm, 32);
    bitmap_set_bit_at(&bm, 33);
    bitmap_set_bit_at(&bm, 50);
    bitmap_set_bit_at(&bm, 51);
    bitmap_set_bit_at(&bm, 60);
    bitmap_set_bit_at(&bm, 61);
    bitmap_set_bit_at(&bm, 63);
    bitmap_t bm1;
    bitmap_init(&bm1, 64);
    bitmap_fast_copy(&bm, &bm1, 64);
    bitmap_print(&bm);
    bitmap_print(&bm1);
    bitmap_prefix_print(&bm, &bm1, 64);
    return 0;
}
#endif