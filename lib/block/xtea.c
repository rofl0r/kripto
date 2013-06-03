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

/* this XTEA implementation is big endian */

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>

#include <kripto/block/xtea.h>

struct kripto_block
{
	kripto_block_desc *desc;
	size_t size;
	unsigned int r;
	uint32_t *k;
};

static void xtea_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	uint32_t c = 0;
	uint32_t k[4] = {0, 0, 0, 0};
	unsigned int i;

	/* big endian */
	for(i = 0; i < key_len; i++)
		k[i >> 2] = (k[i >> 2] << 8) | key[i];

	key_len = (key_len + 3) >> 2;
	i = 0;
	while(i < s->r)
	{
		s->k[i++] = c + k[c % key_len];
		if(i == s->r) break;
		c += 0x9E3779B9;
		s->k[i++] = c + k[(c >> 11) % key_len];
	}
}

#define F(X) ((((X) << 4) ^ ((X) >> 5)) + (X))

static void xtea_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = U8TO32_BE(CU8(pt));
	uint32_t x1 = U8TO32_BE(CU8(pt) + 4);
	unsigned int i = 0;

	while(i < s->r)
	{
		x0 += F(x1) ^ s->k[i++];

		if(i == s->r) break;

		x1 += F(x0) ^ s->k[i++];
	}

	U32TO8_BE(x0, U8(ct));
	U32TO8_BE(x1, U8(ct) + 4);
}
 
static void xtea_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = U8TO32_BE(CU8(ct));
	uint32_t x1 = U8TO32_BE(CU8(ct) + 4);
	unsigned int i = s->r - 1;

	while(i != UINT_MAX)
	{
		x1 -= F(x0) ^ s->k[i--];

		if(i == UINT_MAX) break;

		x0 -= F(x1) ^ s->k[i--];
	}

	U32TO8_BE(x0, U8(pt));
	U32TO8_BE(x1, U8(pt) + 4);
}

static kripto_block *xtea_create
(
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	kripto_block *s;

	if(!r) r = 64;

	s = malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->desc = kripto_block_xtea;
	s->size = sizeof(kripto_block) + (r << 2);
	s->r = r;
	s->k = (uint32_t *)((uint8_t *)s + sizeof(kripto_block));

	xtea_setup(s, key, key_len);

	return s;
}

static void xtea_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *xtea_change
(
	kripto_block *s,
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	if(!r) r = 64;

	if(sizeof(kripto_block) + (r << 2) > s->size)
	{
		xtea_destroy(s);
		s = xtea_create(key, key_len, r);
	}
	else
	{
		s->r = r;

		xtea_setup(s, key, key_len);
	}

	return s;
}

static const struct kripto_block_desc xtea =
{
	&xtea_encrypt,
	&xtea_decrypt,
	&xtea_create,
	&xtea_change,
	&xtea_destroy,
	8, /* block size */
	16, /* max key */
	UINT_MAX, /* max rounds */
	64 /* default rounds */
};

kripto_block_desc *const kripto_block_xtea = &xtea;
