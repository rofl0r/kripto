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

#include <kripto/block/speck128.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint64_t *k;
};

#define R(A, B, K)				\
{								\
	A = (ROR64(A, 8) + B) ^ K;	\
	B = ROL64(B, 3) ^ A;		\
}

#define IR(A, B, K)				\
{								\
	B = ROR64(B ^ A, 3);		\
	A = ROL64((A ^ K) - B, 8);	\
}

static void speck128_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t a;
	uint64_t b;
	unsigned int i;

	a = LOAD64B(CU8(pt));
	b = LOAD64B(CU8(pt) + 8);

	for(i = 0; i < s->rounds; i++)
		R(a, b, s->k[i]);

	STORE64B(a, U8(ct));
	STORE64B(b, U8(ct) + 8);
}

static void speck128_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t a;
	uint64_t b;
	unsigned int i;

	a = LOAD64B(CU8(ct));
	b = LOAD64B(CU8(ct) + 8);

	for(i = s->rounds; i--;)
		IR(a, b, s->k[i]);

	STORE64B(a, U8(pt));
	STORE64B(b, U8(pt) + 8);
}

static void speck128_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	unsigned int m;
	uint64_t k[4] = {0, 0, 0, 0};

	m = ((len + 7) >> 3) - 1;

	for(i = 0; i < len; i++)
		k[m - (i >> 3)] |= (uint64_t)key[i] << (56 - ((i & 7) << 3));

	s->k[0] = k[0];

	for(i = 0; i < s->rounds - 1;)
	{
		R(k[(i % m) + 1], k[0], i);
		s->k[++i] = k[0];
	}

	kripto_memwipe(k, 32);
}

static kripto_block *speck128_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 30 + ((key_len + 7) >> 3);

	s = malloc(sizeof(kripto_block) + (r << 3));
	if(!s) return 0;

	s->obj.desc = kripto_block_speck128;
	s->size = sizeof(kripto_block) + (r << 3);
	s->k = (uint64_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	speck128_setup(s, key, key_len);

	return s;
}

static void speck128_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *speck128_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 30 + ((key_len + 7) >> 3);

	if(sizeof(kripto_block) + (r << 3) > s->size)
	{
		speck128_destroy(s);
		s = speck128_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		speck128_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc speck128 =
{
	&speck128_create,
	&speck128_recreate,
	0,
	&speck128_encrypt,
	&speck128_decrypt,
	&speck128_destroy,
	16, /* block size */
	32 /* max key */
};

const kripto_block_desc *const kripto_block_speck128 = &speck128;
