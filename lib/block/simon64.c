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

#include <kripto/block/simon64.h>

struct kripto_block
{
	const kripto_block_desc *desc;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define F(X) ((ROL32(X, 1) & ROL32(X, 8)) ^ ROL32(X, 2))

static void simon64_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t a;
	uint32_t b;
	unsigned int i = 0;

	a = LOAD32B(CU8(pt));
	b = LOAD32B(CU8(pt) + 4);

	while(i < s->rounds)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE32B(a, U8(ct) + 4);
			STORE32B(b, U8(ct));
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE32B(a, U8(ct));
	STORE32B(b, U8(ct) + 4);
}

static void simon64_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t a;
	uint32_t b;
	unsigned int i = s->rounds;

	a = LOAD32B(CU8(ct));
	b = LOAD32B(CU8(ct) + 4);

	while(i)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE32B(a, U8(pt) + 4);
			STORE32B(b, U8(pt));
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE32B(a, U8(pt));
	STORE32B(b, U8(pt) + 4);
}

static const uint64_t z[2] =
{
	0x3369F885192C0EF5,
	0x3C2CE51207A635DB
};

static void simon64_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	unsigned int m;
	uint32_t t;

	m = (len + 3) >> 2;
	if(m < 3) m = 3;

	for(i = 0; i < m; i++)
		s->k[i] = 0;

	for(i = 0; i < len; i++)
		s->k[m - 1 - (i >> 2)] |=
			(uint32_t)key[i] << (24 - ((i & 3) << 3));

	for(i = m; i < s->rounds; i++)
	{
		t = ROR32(s->k[i - 1], 3);
		if(m == 4) t ^= s->k[i - 3];
		t ^= ROR32(t, 1) ^ ~s->k[i - m] ^ 3;
		s->k[i] = t ^ ((z[m - 3] >> ((i - m) % 62)) & 1);
	}

	kripto_memwipe(&t, sizeof(uint32_t));
}

static kripto_block *simon64_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 36 + (((key_len + 3) >> 2) << 1);

	s = malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->desc = kripto_block_simon64;
	s->size = sizeof(kripto_block) + (r << 2);
	s->k = (uint32_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	simon64_setup(s, key, key_len);

	return s;
}

static void simon64_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *simon64_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 36 + (((key_len + 3) >> 2) << 1);

	if(sizeof(kripto_block) + (r << 2) > s->size)
	{
		simon64_destroy(s);
		s = simon64_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		simon64_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon64 =
{
	&simon64_create,
	&simon64_recreate,
	0,
	&simon64_encrypt,
	&simon64_decrypt,
	&simon64_destroy,
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_simon64 = &simon64;
