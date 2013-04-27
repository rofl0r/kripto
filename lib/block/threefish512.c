/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>

#include <kripto/block/threefish512.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	kripto_block_desc desc;
	unsigned int r;
	uint64_t t[3];
	uint64_t k[9];
};

void kripto_block_threefish512_tweak(kripto_block s, const void *tweak)
{
	s->t[0] = U8TO64_LE(CU8(tweak));
	s->t[1] = U8TO64_LE(CU8(tweak) + 8);
	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish512_encrypt
(
	const kripto_block s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = U8TO64_LE(CU8(pt)) + s->k[0];
	uint64_t x1 = U8TO64_LE(CU8(pt) + 8) + s->k[1];
	uint64_t x2 = U8TO64_LE(CU8(pt) + 16) + s->k[2];
	uint64_t x3 = U8TO64_LE(CU8(pt) + 24) + s->k[3];
	uint64_t x4 = U8TO64_LE(CU8(pt) + 32) + s->k[4];
	uint64_t x5 = U8TO64_LE(CU8(pt) + 40) + s->k[5] + s->t[0];
	uint64_t x6 = U8TO64_LE(CU8(pt) + 48) + s->k[6] + s->t[1];
	uint64_t x7 = U8TO64_LE(CU8(pt) + 56) + s->k[7];
	unsigned int r = 1;

	while(r <= s->r)
	{
		x0 += x1; x1 = ROL64(x1, 46); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 36); x3 ^= x2;
		x4 += x5; x5 = ROL64(x5, 19); x5 ^= x4;
		x6 += x7; x7 = ROL64(x7, 37); x7 ^= x6;

		x2 += x1; x1 = ROL64(x1, 33); x1 ^= x2;
		x4 += x7; x7 = ROL64(x7, 27); x7 ^= x4;
		x6 += x5; x5 = ROL64(x5, 14); x5 ^= x6;
		x0 += x3; x3 = ROL64(x3, 42); x3 ^= x0;

		x4 += x1; x1 = ROL64(x1, 17); x1 ^= x4;
		x6 += x3; x3 = ROL64(x3, 49); x3 ^= x6;
		x0 += x5; x5 = ROL64(x5, 36); x5 ^= x0;
		x2 += x7; x7 = ROL64(x7, 39); x7 ^= x2;
		
		x6 += x1; x1 = ROL64(x1, 44); x1 ^= x6;
		x0 += x7; x7 = ROL64(x7, 9); x7 ^= x0;
		x2 += x5; x5 = ROL64(x5, 54); x5 ^= x2;
		x4 += x3; x3 = ROL64(x3, 56); x3 ^= x4;

		x0 += s->k[r % 9];
		x1 += s->k[(r + 1) % 9];
		x2 += s->k[(r + 2) % 9];
		x3 += s->k[(r + 3) % 9];
		x4 += s->k[(r + 4) % 9];
		x5 += s->k[(r + 5) % 9] + s->t[r % 3];
		x6 += s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 += s->k[(r + 7) % 9] + r;
		r++;

		x0 += x1; x1 = ROL64(x1, 39); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 30); x3 ^= x2;
		x4 += x5; x5 = ROL64(x5, 34); x5 ^= x4;
		x6 += x7; x7 = ROL64(x7, 24); x7 ^= x6;

		x2 += x1; x1 = ROL64(x1, 13); x1 ^= x2;
		x4 += x7; x7 = ROL64(x7, 50); x7 ^= x4;
		x6 += x5; x5 = ROL64(x5, 10); x5 ^= x6;
		x0 += x3; x3 = ROL64(x3, 17); x3 ^= x0;

		x4 += x1; x1 = ROL64(x1, 25); x1 ^= x4;
		x6 += x3; x3 = ROL64(x3, 29); x3 ^= x6;
		x0 += x5; x5 = ROL64(x5, 39); x5 ^= x0;
		x2 += x7; x7 = ROL64(x7, 43); x7 ^= x2;
		
		x6 += x1; x1 = ROL64(x1, 8); x1 ^= x6;
		x0 += x7; x7 = ROL64(x7, 35); x7 ^= x0;
		x2 += x5; x5 = ROL64(x5, 56); x5 ^= x2;
		x4 += x3; x3 = ROL64(x3, 22); x3 ^= x4;

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

	U64TO8_LE(x0, U8(ct));
	U64TO8_LE(x1, U8(ct) + 8);
	U64TO8_LE(x2, U8(ct) + 16);
	U64TO8_LE(x3, U8(ct) + 24);
	U64TO8_LE(x4, U8(ct) + 32);
	U64TO8_LE(x5, U8(ct) + 40);
	U64TO8_LE(x6, U8(ct) + 48);
	U64TO8_LE(x7, U8(ct) + 56);
}

static void threefish512_decrypt
(
	const kripto_block s,
	const void *ct,
	void *pt
)
{
	uint64_t x0 = U8TO64_LE(CU8(ct));
	uint64_t x1 = U8TO64_LE(CU8(ct) + 8);
	uint64_t x2 = U8TO64_LE(CU8(ct) + 16);
	uint64_t x3 = U8TO64_LE(CU8(ct) + 24);
	uint64_t x4 = U8TO64_LE(CU8(ct) + 32);
	uint64_t x5 = U8TO64_LE(CU8(ct) + 40);
	uint64_t x6 = U8TO64_LE(CU8(ct) + 48);
	uint64_t x7 = U8TO64_LE(CU8(ct) + 56);
	unsigned int r = s->r;

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

		x3 = ROR64(x3 ^ x4, 22); x4 -= x3;
		x5 = ROR64(x5 ^ x2, 56); x2 -= x5;
		x7 = ROR64(x7 ^ x0, 35); x0 -= x7;
		x1 = ROR64(x1 ^ x6, 8); x6 -= x1;

		x7 = ROR64(x7 ^ x2, 43); x2 -= x7;
		x5 = ROR64(x5 ^ x0, 39); x0 -= x5;
		x3 = ROR64(x3 ^ x6, 29); x6 -= x3;
		x1 = ROR64(x1 ^ x4, 25); x4 -= x1;

		x3 = ROR64(x3 ^ x0, 17); x0 -= x3;
		x5 = ROR64(x5 ^ x6, 10); x6 -= x5;
		x7 = ROR64(x7 ^ x4, 50); x4 -= x7;
		x1 = ROR64(x1 ^ x2, 13); x2 -= x1;

		x7 = ROR64(x7 ^ x6, 24); x6 -= x7;
		x5 = ROR64(x5 ^ x4, 34); x4 -= x5;
		x3 = ROR64(x3 ^ x2, 30); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 39); x0 -= x1;

		x0 -= s->k[r % 9];
		x1 -= s->k[(r + 1) % 9];
		x2 -= s->k[(r + 2) % 9];
		x3 -= s->k[(r + 3) % 9];
		x4 -= s->k[(r + 4) % 9];
		x5 -= s->k[(r + 5) % 9] + s->t[r % 3];
		x6 -= s->k[(r + 6) % 9] + s->t[(r + 1) % 3];
		x7 -= s->k[(r + 7) % 9] + r;
		r--;

		x3 = ROR64(x3 ^ x4, 56); x4 -= x3;
		x5 = ROR64(x5 ^ x2, 54); x2 -= x5;
		x7 = ROR64(x7 ^ x0, 9); x0 -= x7;
		x1 = ROR64(x1 ^ x6, 44); x6 -= x1;

		x7 = ROR64(x7 ^ x2, 39); x2 -= x7;
		x5 = ROR64(x5 ^ x0, 36); x0 -= x5;
		x3 = ROR64(x3 ^ x6, 49); x6 -= x3;
		x1 = ROR64(x1 ^ x4, 17); x4 -= x1;

		x3 = ROR64(x3 ^ x0, 42); x0 -= x3;
		x5 = ROR64(x5 ^ x6, 14); x6 -= x5;
		x7 = ROR64(x7 ^ x4, 27); x4 -= x7;
		x1 = ROR64(x1 ^ x2, 33); x2 -= x1;

		x7 = ROR64(x7 ^ x6, 37); x6 -= x7;
		x5 = ROR64(x5 ^ x4, 19); x4 -= x5;
		x3 = ROR64(x3 ^ x2, 36); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 46); x0 -= x1;
	}

	x0 -= s->k[0];
	x1 -= s->k[1];
	x2 -= s->k[2];
	x3 -= s->k[3];
	x4 -= s->k[4];
	x5 -= s->k[5] + s->t[0];
	x6 -= s->k[6] + s->t[1];
	x7 -= s->k[7];

	U64TO8_LE(x0, U8(pt));
	U64TO8_LE(x1, U8(pt) + 8);
	U64TO8_LE(x2, U8(pt) + 16);
	U64TO8_LE(x3, U8(pt) + 24);
	U64TO8_LE(x4, U8(pt) + 32);
	U64TO8_LE(x5, U8(pt) + 40);
	U64TO8_LE(x6, U8(pt) + 48);
	U64TO8_LE(x7, U8(pt) + 56);
}

static kripto_block threefish512_create
(
	const void *key,
	const unsigned int key_len,
	const unsigned int r
)
{
	kripto_block s;
	unsigned int i;

	if(key_len > 64) return 0;

	s = malloc(sizeof(struct kripto_block));
	if(!s) return 0;

	s->desc = kripto_block_threefish512;
	s->r = ((r + 7) >> 3) << 1;
	if(!s->r) s->r = 18; /* 72 / 4 */

	memset(s->k, 0, 64);

	for(i = key_len - 1; i != UINT_MAX; i--)
		s->k[i >> 3] = (s->k[i >> 3] << 8) | CU8(key)[i];

	s->k[8] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3]
		^ s->k[4] ^ s->k[5] ^ s->k[6] ^ s->k[7] ^ C240;

	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static void threefish512_destroy(kripto_block s)
{
	kripto_memwipe(s, sizeof(struct kripto_block));
	free(s);
}

static const struct kripto_block_desc threefish512 =
{
	&threefish512_encrypt,
	&threefish512_decrypt,
	&threefish512_create,
	&threefish512_destroy,
	64,
	64,
	UINT_MAX,
	72
};

kripto_block_desc const kripto_block_threefish512 = &threefish512;
