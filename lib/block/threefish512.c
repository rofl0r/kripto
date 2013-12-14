/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/threefish512.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	uint64_t t[3];
	uint64_t k[9];
};

static void threefish512_tweak
(
	kripto_block *s,
	const void *tweak,
	unsigned int len
)
{
	s->t[0] = s->t[1] = 0;

	while(--len != UINT_MAX)
		s->t[len >> 3] = (s->t[len >> 3] << 8) | CU8(tweak)[len];

	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish512_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = LOAD64L(CU8(pt)) + s->k[0];
	uint64_t x1 = LOAD64L(CU8(pt) + 8) + s->k[1];
	uint64_t x2 = LOAD64L(CU8(pt) + 16) + s->k[2];
	uint64_t x3 = LOAD64L(CU8(pt) + 24) + s->k[3];
	uint64_t x4 = LOAD64L(CU8(pt) + 32) + s->k[4];
	uint64_t x5 = LOAD64L(CU8(pt) + 40) + s->k[5] + s->t[0];
	uint64_t x6 = LOAD64L(CU8(pt) + 48) + s->k[6] + s->t[1];
	uint64_t x7 = LOAD64L(CU8(pt) + 56) + s->k[7];
	unsigned int r = 1;

	while(r <= s->rounds >> 2)
	{
		x0 += x1; x1 = ROL64_46(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_36(x3); x3 ^= x2;
		x4 += x5; x5 = ROL64_19(x5); x5 ^= x4;
		x6 += x7; x7 = ROL64_37(x7); x7 ^= x6;

		x2 += x1; x1 = ROL64_33(x1); x1 ^= x2;
		x4 += x7; x7 = ROL64_27(x7); x7 ^= x4;
		x6 += x5; x5 = ROL64_14(x5); x5 ^= x6;
		x0 += x3; x3 = ROL64_42(x3); x3 ^= x0;

		x4 += x1; x1 = ROL64_17(x1); x1 ^= x4;
		x6 += x3; x3 = ROL64_49(x3); x3 ^= x6;
		x0 += x5; x5 = ROL64_36(x5); x5 ^= x0;
		x2 += x7; x7 = ROL64_39(x7); x7 ^= x2;
		
		x6 += x1; x1 = ROL64_44(x1); x1 ^= x6;
		x0 += x7; x7 = ROL64_09(x7); x7 ^= x0;
		x2 += x5; x5 = ROL64_54(x5); x5 ^= x2;
		x4 += x3; x3 = ROL64_56(x3); x3 ^= x4;

		x0 += s->k[r % 9];
		x1 += s->k[(r + 1) % 9];
		x2 += s->k[(r + 2) % 9];
		x3 += s->k[(r + 3) % 9];
		x4 += s->k[(r + 4) % 9];
		x5 += s->k[(r + 5) % 9] + s->t[r % 3];
		x6 += s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 += s->k[(r + 7) % 9] + r;
		r++;

		x0 += x1; x1 = ROL64_39(x1); x1 ^= x0;
		x2 += x3; x3 = ROL64_30(x3); x3 ^= x2;
		x4 += x5; x5 = ROL64_34(x5); x5 ^= x4;
		x6 += x7; x7 = ROL64_24(x7); x7 ^= x6;

		x2 += x1; x1 = ROL64_13(x1); x1 ^= x2;
		x4 += x7; x7 = ROL64_50(x7); x7 ^= x4;
		x6 += x5; x5 = ROL64_10(x5); x5 ^= x6;
		x0 += x3; x3 = ROL64_17(x3); x3 ^= x0;

		x4 += x1; x1 = ROL64_25(x1); x1 ^= x4;
		x6 += x3; x3 = ROL64_29(x3); x3 ^= x6;
		x0 += x5; x5 = ROL64_39(x5); x5 ^= x0;
		x2 += x7; x7 = ROL64_43(x7); x7 ^= x2;
		
		x6 += x1; x1 = ROL64_08(x1); x1 ^= x6;
		x0 += x7; x7 = ROL64_35(x7); x7 ^= x0;
		x2 += x5; x5 = ROL64_56(x5); x5 ^= x2;
		x4 += x3; x3 = ROL64_22(x3); x3 ^= x4;

		x0 += s->k[r % 9];
		x1 += s->k[(r + 1) % 9];
		x2 += s->k[(r + 2) % 9];
		x3 += s->k[(r + 3) % 9];
		x4 += s->k[(r + 4) % 9];
		x5 += s->k[(r + 5) % 9] + s->t[r % 3];
		x6 += s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 += s->k[(r + 7) % 9] + r;
		r++;
	}

	STORE64L(x0, U8(ct));
	STORE64L(x1, U8(ct) + 8);
	STORE64L(x2, U8(ct) + 16);
	STORE64L(x3, U8(ct) + 24);
	STORE64L(x4, U8(ct) + 32);
	STORE64L(x5, U8(ct) + 40);
	STORE64L(x6, U8(ct) + 48);
	STORE64L(x7, U8(ct) + 56);
}

static void threefish512_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t x0 = LOAD64L(CU8(ct));
	uint64_t x1 = LOAD64L(CU8(ct) + 8);
	uint64_t x2 = LOAD64L(CU8(ct) + 16);
	uint64_t x3 = LOAD64L(CU8(ct) + 24);
	uint64_t x4 = LOAD64L(CU8(ct) + 32);
	uint64_t x5 = LOAD64L(CU8(ct) + 40);
	uint64_t x6 = LOAD64L(CU8(ct) + 48);
	uint64_t x7 = LOAD64L(CU8(ct) + 56);
	unsigned int r = s->rounds >> 2;

	while(r > 1)
	{
		x0 -= s->k[r % 9];
		x1 -= s->k[(r + 1) % 9];
		x2 -= s->k[(r + 2) % 9];
		x3 -= s->k[(r + 3) % 9];
		x4 -= s->k[(r + 4) % 9];
		x5 -= s->k[(r + 5) % 9] + s->t[r % 3];
		x6 -= s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 -= s->k[(r + 7) % 9] + r;
		r--;

		x3 = ROR64_22(x3 ^ x4); x4 -= x3;
		x5 = ROR64_56(x5 ^ x2); x2 -= x5;
		x7 = ROR64_35(x7 ^ x0); x0 -= x7;
		x1 = ROR64_08(x1 ^ x6); x6 -= x1;
                             
		x7 = ROR64_43(x7 ^ x2); x2 -= x7;
		x5 = ROR64_39(x5 ^ x0); x0 -= x5;
		x3 = ROR64_29(x3 ^ x6); x6 -= x3;
		x1 = ROR64_25(x1 ^ x4); x4 -= x1;
                             
		x3 = ROR64_17(x3 ^ x0); x0 -= x3;
		x5 = ROR64_10(x5 ^ x6); x6 -= x5;
		x7 = ROR64_50(x7 ^ x4); x4 -= x7;
		x1 = ROR64_13(x1 ^ x2); x2 -= x1;
                             
		x7 = ROR64_24(x7 ^ x6); x6 -= x7;
		x5 = ROR64_34(x5 ^ x4); x4 -= x5;
		x3 = ROR64_30(x3 ^ x2); x2 -= x3;
		x1 = ROR64_39(x1 ^ x0); x0 -= x1;

		x0 -= s->k[r % 9];
		x1 -= s->k[(r + 1) % 9];
		x2 -= s->k[(r + 2) % 9];
		x3 -= s->k[(r + 3) % 9];
		x4 -= s->k[(r + 4) % 9];
		x5 -= s->k[(r + 5) % 9] + s->t[r % 3];
		x6 -= s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 -= s->k[(r + 7) % 9] + r;
		r--;

		x3 = ROR64_56(x3 ^ x4); x4 -= x3;
		x5 = ROR64_54(x5 ^ x2); x2 -= x5;
		x7 = ROR64_09(x7 ^ x0); x0 -= x7;
		x1 = ROR64_44(x1 ^ x6); x6 -= x1;

		x7 = ROR64_39(x7 ^ x2); x2 -= x7;
		x5 = ROR64_36(x5 ^ x0); x0 -= x5;
		x3 = ROR64_49(x3 ^ x6); x6 -= x3;
		x1 = ROR64_17(x1 ^ x4); x4 -= x1;

		x3 = ROR64_42(x3 ^ x0); x0 -= x3;
		x5 = ROR64_14(x5 ^ x6); x6 -= x5;
		x7 = ROR64_27(x7 ^ x4); x4 -= x7;
		x1 = ROR64_33(x1 ^ x2); x2 -= x1;

		x7 = ROR64_37(x7 ^ x6); x6 -= x7;
		x5 = ROR64_19(x5 ^ x4); x4 -= x5;
		x3 = ROR64_36(x3 ^ x2); x2 -= x3;
		x1 = ROR64_46(x1 ^ x0); x0 -= x1;
	}

	x0 -= s->k[0];
	x1 -= s->k[1];
	x2 -= s->k[2];
	x3 -= s->k[3];
	x4 -= s->k[4];
	x5 -= s->k[5] + s->t[0];
	x6 -= s->k[6] + s->t[1];
	x7 -= s->k[7];

	STORE64L(x0, U8(pt));
	STORE64L(x1, U8(pt) + 8);
	STORE64L(x2, U8(pt) + 16);
	STORE64L(x3, U8(pt) + 24);
	STORE64L(x4, U8(pt) + 32);
	STORE64L(x5, U8(pt) + 40);
	STORE64L(x6, U8(pt) + 48);
	STORE64L(x7, U8(pt) + 56);
}

static kripto_block *threefish512_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;

	s->rounds = r;
	if(!s->rounds) s->rounds = 72;

	memset(s->k, 0, 64);

	for(i = key_len - 1; i != UINT_MAX; i--)
		s->k[i >> 3] = (s->k[i >> 3] << 8) | CU8(key)[i];

	s->k[8] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3]
		^ s->k[4] ^ s->k[5] ^ s->k[6] ^ s->k[7] ^ C240;

	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static kripto_block *threefish512_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_threefish512;

	(void)threefish512_recreate(s, r, key, key_len);

	return s;
}

static void threefish512_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc threefish512 =
{
	&threefish512_create,
	&threefish512_recreate,
	&threefish512_tweak,
	&threefish512_encrypt,
	&threefish512_decrypt,
	&threefish512_destroy,
	"Threefish512",
	64, /* block size */
	64 /* max key */
};

const kripto_block_desc *const kripto_block_threefish512 = &threefish512;
