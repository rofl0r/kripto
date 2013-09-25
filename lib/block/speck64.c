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
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>

#include <kripto/block/speck64.h>

struct kripto_block
{
	const kripto_block_desc *desc;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define R(A, B, K)				\
{								\
	A = (ROR32(A, 8) + B) ^ K;	\
	B = ROL32(B, 3) ^ A;		\
}

#define IR(A, B, K)				\
{								\
	B = ROR32(B ^ A, 3);		\
	A = ROL32((A ^ K) - B, 8);	\
}

static void speck64_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a;
	uint32_t b;
	unsigned int i;

	a = LOAD32B(CU8(pt));
	b = LOAD32B(CU8(pt) + 4);

	for(i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE32B(a, U8(ct));
	STORE32B(b, U8(ct) + 4);
}

static void speck64_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a;
	uint32_t b;
	unsigned int i;

	a = LOAD32B(CU8(ct));
	b = LOAD32B(CU8(ct) + 4);

	for(i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE32B(a, U8(pt));
	STORE32B(b, U8(pt) + 4);
}

static void speck64_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	unsigned int m;
	uint32_t k[4] = {0, 0, 0, 0};

	m = ((len + 3) >> 2) - 1;

	for(i = 0; i < len; i++)
		k[m - (i >> 2)] |= (uint32_t)key[i] << (24 - ((i & 3) << 3));

	s->k[0] = k[0];

	for(i = 0; i < s->rounds - 1;)
	{
		R(k[(i % m) + 1], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memwipe(k, 16);
}

static kripto_block *speck64_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 23 + ((key_len + 3) >> 2);

	s = malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->desc = kripto_block_speck64;
	s->size = sizeof(kripto_block) + (r << 2);
	s->k = (uint32_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	speck64_setup(s, key, key_len);

	return s;
}

static void speck64_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *speck64_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 23 + ((key_len + 3) >> 2);

	if(sizeof(kripto_block) + (r << 2) > s->size)
	{
		speck64_destroy(s);
		s = speck64_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		speck64_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc speck64 =
{
	&speck64_create,
	&speck64_recreate,
	0,
	&speck64_encrypt,
	&speck64_decrypt,
	&speck64_destroy,
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_speck64 = &speck64;
