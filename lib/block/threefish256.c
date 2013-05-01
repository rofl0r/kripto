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

#include <kripto/block/threefish256.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	kripto_block_desc *desc;
	unsigned int r;
	uint64_t t[3];
	uint64_t k[5];
};

void kripto_block_threefish256_tweak(kripto_block *s, const void *tweak)
{
	s->t[0] = U8TO64_LE(CU8(tweak));
	s->t[1] = U8TO64_LE(CU8(tweak) + 8);
	s->t[2] = s->t[0] ^ s->t[1];
}

static void threefish256_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = U8TO64_LE(CU8(pt)) + s->k[0];
	uint64_t x1 = U8TO64_LE(CU8(pt) + 8) + s->k[1] + s->t[0];
	uint64_t x2 = U8TO64_LE(CU8(pt) + 16) + s->k[2] + s->t[1];
	uint64_t x3 = U8TO64_LE(CU8(pt) + 24) + s->k[3];
	unsigned int r = 1;

	while(r <= s->r)
	{
		x0 += x1; x1 = ROL64(x1, 14); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 16); x3 ^= x2;

		x0 += x3; x3 = ROL64(x3, 52); x3 ^= x0;
		x2 += x1; x1 = ROL64(x1, 57); x1 ^= x2;

		x0 += x1; x1 = ROL64(x1, 23); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 40); x3 ^= x2;

		x0 += x3; x3 = ROL64(x3, 5); x3 ^= x0;
		x2 += x1; x1 = ROL64(x1, 37); x1 ^= x2;

		x0 += s->k[r % 5];
		x1 += s->k[(r + 1) % 5] + s->t[r % 3];
		x2 += s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 += s->k[(r + 3) % 5] + r;
		r++;

		x0 += x1; x1 = ROL64(x1, 25); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 33); x3 ^= x2;

		x0 += x3; x3 = ROL64(x3, 46); x3 ^= x0;
		x2 += x1; x1 = ROL64(x1, 12); x1 ^= x2;

		x0 += x1; x1 = ROL64(x1, 58); x1 ^= x0;
		x2 += x3; x3 = ROL64(x3, 22); x3 ^= x2;

		x0 += x3; x3 = ROL64(x3, 32); x3 ^= x0;
		x2 += x1; x1 = ROL64(x1, 32); x1 ^= x2;

		x0 += s->k[r % 5];
		x1 += s->k[(r + 1) % 5] + s->t[r % 3];
		x2 += s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 += s->k[(r + 3) % 5] + r;
		r++;
	}

	U64TO8_LE(x0, U8(ct));
	U64TO8_LE(x1, U8(ct) + 8);
	U64TO8_LE(x2, U8(ct) + 16);
	U64TO8_LE(x3, U8(ct) + 24);
}

static void threefish256_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t x0 = U8TO64_LE(CU8(ct));
	uint64_t x1 = U8TO64_LE(CU8(ct) + 8);
	uint64_t x2 = U8TO64_LE(CU8(ct) + 16);
	uint64_t x3 = U8TO64_LE(CU8(ct) + 24);
	unsigned int r = s->r;

	while(r > 1)
	{
		x0 -= s->k[r % 5];
		x1 -= s->k[(r + 1) % 5] + s->t[r % 3];
		x2 -= s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 -= s->k[(r + 3) % 5] + r;
		r--;

		x1 = ROR64(x1 ^ x2, 32); x2 -= x1;
		x3 = ROR64(x3 ^ x0, 32); x0 -= x3;

		x3 = ROR64(x3 ^ x2, 22); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 58); x0 -= x1;

		x1 = ROR64(x1 ^ x2, 12); x2 -= x1;
		x3 = ROR64(x3 ^ x0, 46); x0 -= x3;

		x3 = ROR64(x3 ^ x2, 33); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 25); x0 -= x1;

		x0 -= s->k[r % 5];
		x1 -= s->k[(r + 1) % 5] + s->t[r % 3];
		x2 -= s->k[(r + 2) % 5] + s->t[(r + 1) % 3];
		x3 -= s->k[(r + 3) % 5] + r;
		r--;

		x1 = ROR64(x1 ^ x2, 37); x2 -= x1;
		x3 = ROR64(x3 ^ x0, 5); x0 -= x3;

		x3 = ROR64(x3 ^ x2, 40); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 23); x0 -= x1;

		x1 = ROR64(x1 ^ x2, 57); x2 -= x1;
		x3 = ROR64(x3 ^ x0, 52); x0 -= x3;

		x3 = ROR64(x3 ^ x2, 16); x2 -= x3;
		x1 = ROR64(x1 ^ x0, 14); x0 -= x1;
	}

	x0 -= s->k[0];
	x1 -= s->k[1] + s->t[0];
	x2 -= s->k[2] + s->t[1];
	x3 -= s->k[3];

	U64TO8_LE(x0, U8(pt));
	U64TO8_LE(x1, U8(pt) + 8);
	U64TO8_LE(x2, U8(pt) + 16);
	U64TO8_LE(x3, U8(pt) + 24);
}

static kripto_block *threefish256_create
(
	const void *key,
	const unsigned int key_len,
	const unsigned int r
)
{
	kripto_block *s;
	unsigned int i;

	if(key_len > 32) return 0;

	s = malloc(sizeof(struct kripto_block));
	if(!s) return 0;

	s->desc = kripto_block_threefish256;
	s->r = ((r + 7) >> 3) << 1;
	if(!s->r) s->r = 18; /* 72 / 4 */

	memset(s->k, 0, 32);

	for(i = key_len - 1; i != UINT_MAX; i--)
		s->k[i >> 3] = (s->k[i >> 3] << 8) | CU8(key)[i];

	s->k[4] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3] ^ C240;

	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static void threefish256_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(struct kripto_block));
	free(s);
}

static const struct kripto_block_desc threefish256 =
{
	&threefish256_encrypt,
	&threefish256_decrypt,
	&threefish256_create,
	&threefish256_destroy,
	32,
	32,
	UINT_MAX,
	72
};

kripto_block_desc *const kripto_block_threefish256 = &threefish256;
