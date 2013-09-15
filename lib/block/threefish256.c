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

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/threefish256.h>

#define C240 0x1BD11BDAA9FC1A22

struct kripto_block
{
	const kripto_block_desc *desc;
	unsigned int rounds;
	uint64_t t[3];
	uint64_t k[5];
};

static void threefish256_tweak
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

static void threefish256_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t x0 = LOAD64L(CU8(pt)) + s->k[0];
	uint64_t x1 = LOAD64L(CU8(pt) + 8) + s->k[1] + s->t[0];
	uint64_t x2 = LOAD64L(CU8(pt) + 16) + s->k[2] + s->t[1];
	uint64_t x3 = LOAD64L(CU8(pt) + 24) + s->k[3];
	unsigned int r = 1;

	while(r <= s->rounds >> 2)
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

	STORE64L(x0, U8(ct));
	STORE64L(x1, U8(ct) + 8);
	STORE64L(x2, U8(ct) + 16);
	STORE64L(x3, U8(ct) + 24);
}

static void threefish256_decrypt
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
	unsigned int r = s->rounds >> 2;

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

	STORE64L(x0, U8(pt));
	STORE64L(x1, U8(pt) + 8);
	STORE64L(x2, U8(pt) + 16);
	STORE64L(x3, U8(pt) + 24);
}

static kripto_block *threefish256_recreate
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

	memset(s->k, 0, 32);

	for(i = key_len - 1; i != UINT_MAX; i--)
		s->k[i >> 3] = (s->k[i >> 3] << 8) | CU8(key)[i];

	s->k[4] = s->k[0] ^ s->k[1] ^ s->k[2] ^ s->k[3] ^ C240;

	s->t[0] = s->t[1] = s->t[2] = 0;

	return s;
}

static kripto_block *threefish256_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->desc = kripto_block_threefish256;

	(void)threefish256_recreate(s, r, key, key_len);

	return s;
}

static void threefish256_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc threefish256 =
{
	&threefish256_create,
	&threefish256_recreate,
	&threefish256_tweak,
	&threefish256_encrypt,
	&threefish256_decrypt,
	&threefish256_destroy,
	32, /* block size */
	32 /* max key */
};

const kripto_block_desc *const kripto_block_threefish256 = &threefish256;
