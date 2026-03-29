/* Assuming least significant bit starts from 0th bit*/

#ifndef __BITS__
#define __BITS__

#define IS_BIT_SET(n, pos)	((n & (pos)) != 0)
#define TOGGLE_BIT(n, pos)	(n = n ^ (pos))
#define COMPLEMENT8(num)	   	(num = num ^ 0xFF)
#define COMPLEMENT32(num)	   	(num = num ^ 0xFFFFFFFF)
#define COMPLEMENT16(num)	   	(num = num ^ 0xFFFF)
#define COMPLEMENT64(num)	   	(num = num ^ 0xFFFFFFFFFFFFFFFF)
#define UNSET_BIT32(n, pos)  	(n = n & ((pos) ^ 0xFFFFFFFF))
#define UNSET_BIT64(n, pos)  	(n = n & ((pos) ^ 0xFFFFFFFFFFFFFFFF))
#define UNSET_BIT16(n, pos)  	(n = n & ((pos) ^ 0xFFFF))
#define UNSET_BIT8(n, pos)  	(n = n & ((pos) ^ 0xFF))

#define SET_BIT(n, pos)     (n = n | pos)

#endif

