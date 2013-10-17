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
#include <kripto/object/block.h>

#include <kripto/block/speck32.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint16_t *k;
};

#define R(A, B, K)				\
{								\
	A = (ROR16(A, 7) + B) ^ K;	\
	B = ROL16(B, 2) ^ A;		\
}

#define IR(A, B, K)				\
{								\
	B = ROR16(B ^ A, 2);		\
	A = ROL16((A ^ K) - B, 7);	\
}

static void speck32_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint16_t a;
	uint16_t b;
	unsigned int i;

	a = LOAD16B(CU8(pt));
	b = LOAD16B(CU8(pt) + 2);

	for(i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE16B(a, U8(ct));
	STORE16B(b, U8(ct) + 2);
}

static void speck32_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint16_t a;
	uint16_t b;
	unsigned int i;

	a = LOAD16B(CU8(ct));
	b = LOAD16B(CU8(ct) + 2);

	for(i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE16B(a, U8(pt));
	STORE16B(b, U8(pt) + 2);
}

static void speck32_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	unsigned int m;
	uint16_t k[4] = {0, 0, 0, 0};

	m = ((len + 1) >> 1) - 1;

	for(i = 0; i < len; i++)
		k[m - (i >> 1)] |= (uint16_t)key[i] << (8 - ((i & 1) << 3));

	s->k[0] = k[0];

	for(i = 0; i < s->rounds - 1;)
	{
		R(k[(i % m) + 1], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memwipe(k, 8);
}

static kripto_block *speck32_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 22;

	s = malloc(sizeof(kripto_block) + (r << 1));
	if(!s) return 0;

	s->obj.desc = kripto_block_speck32;
	s->size = sizeof(kripto_block) + (r << 1);
	s->k = (uint16_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	speck32_setup(s, key, key_len);

	return s;
}

static void speck32_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *speck32_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 22;

	if(sizeof(kripto_block) + (r << 1) > s->size)
	{
		speck32_destroy(s);
		s = speck32_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		speck32_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc speck32 =
{
	&speck32_create,
	&speck32_recreate,
	0,
	&speck32_encrypt,
	&speck32_decrypt,
	&speck32_destroy,
	4, /* block size */
	8 /* max key */
};

const kripto_block_desc *const kripto_block_speck32 = &speck32;
