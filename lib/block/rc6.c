/*
 * Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
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

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>

#include <kripto/block/rc6.h>

struct kripto_block
{
	const kripto_block_desc *desc;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define RC6_K_LEN(r) (((r) + 2) << 1)

static void rc6_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	const unsigned int ls = (key_len + 3) >> 2;
	uint32_t a;
	uint32_t b;
	uint32_t x[64];

	for(i = 0; i < ls; i++) x[i] = 0;

	for(j = key_len - 1; j != UINT_MAX; j--)
		x[j >> 2] = (x[j >> 2] << 8) | key[j];

	*s->k = 0xB7E15163;
	for(i = 1; i < RC6_K_LEN(s->rounds); i++)
		s->k[i] = s->k[i-1] + 0x9E3779B9;

	a = b = i = j = k = 0;
	while(k < RC6_K_LEN(s->rounds) * 3)
	{
		a = s->k[i] = ROL32(s->k[i] + a + b, 3);
		b = x[j] = ROL32(x[j] + a + b, a + b);
		if(++i == RC6_K_LEN(s->rounds)) i = 0;
		if(++j == ls) j = 0;
		k++;
	}

	/* wipe */
	kripto_memwipe(x, ls << 2);
	kripto_memwipe(&a, sizeof(uint32_t));
	kripto_memwipe(&b, sizeof(uint32_t));
}

static void rc6_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t m0;
	uint32_t m1;
	uint32_t t;
	unsigned int i = 2;

	a = U8TO32_LE(CU8(pt));
	b = U8TO32_LE(CU8(pt) + 4);
	c = U8TO32_LE(CU8(pt) + 8);
	d = U8TO32_LE(CU8(pt) + 12);

	b += s->k[0];
	d += s->k[1];

	while(i <= (s->rounds << 1))
	{
		m0 = ROL32(b * ((b << 1) | 1), 5);
		m1 = ROL32(d * ((d << 1) | 1), 5);

		t = ROL32(a ^ m0, m1 & 31) + s->k[i++];
		a = b;
		b = ROL32(c ^ m1, m0 & 31) + s->k[i++];
		c = d;
		d = t;
	}

	a += s->k[i];
	c += s->k[i + 1];

	U32TO8_LE(a, U8(ct));
	U32TO8_LE(b, U8(ct) + 4);
	U32TO8_LE(c, U8(ct) + 8);
	U32TO8_LE(d, U8(ct) + 12);
}

static void rc6_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t m0;
	uint32_t m1;
	uint32_t t;
	unsigned int i = s->rounds << 1;

	a = U8TO32_LE(CU8(ct));
	b = U8TO32_LE(CU8(ct) + 4);
	c = U8TO32_LE(CU8(ct) + 8);
	d = U8TO32_LE(CU8(ct) + 12);

	a -= s->k[i + 2];
	c -= s->k[i + 3];

	while(i)
	{
		m0 = ROL32(a * ((a << 1) | 1), 5);
		m1 = ROL32(c * ((c << 1) | 1), 5);

		t = d;
		d = c;
		c = ROR32(b - s->k[i + 1], m0 & 31) ^ m1;
		b = a;
		a = ROR32(t - s->k[i], m1 & 31) ^ m0;

		i -= 2;
	}

	b -= s->k[0];
	d -= s->k[1];

	U32TO8_LE(a, U8(pt));
	U32TO8_LE(b, U8(pt) + 4);
	U32TO8_LE(c, U8(pt) + 8);
	U32TO8_LE(d, U8(pt) + 12);
}

static kripto_block *rc6_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 20;

	s = malloc(sizeof(kripto_block) + (RC6_K_LEN(r) << 2));
	if(!s) return 0;

	s->desc = kripto_block_rc6;
	s->size = sizeof(kripto_block) + (RC6_K_LEN(r) << 2);
	s->rounds = r;
	s->k = (uint32_t *)((uint8_t *)s + sizeof(kripto_block));

	rc6_setup(s, key, key_len);

	return s;
}

static void rc6_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *rc6_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 20;

	if(sizeof(kripto_block) + (RC6_K_LEN(r) << 2) > s->size)
	{
		rc6_destroy(s);
		s = rc6_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		rc6_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc rc6 =
{
	&rc6_create,
	&rc6_recreate,
	&rc6_encrypt,
	&rc6_decrypt,
	&rc6_destroy,
	16, /* block size */
	255 /* max key */
};

const kripto_block_desc *const kripto_block_rc6 = &rc6;
