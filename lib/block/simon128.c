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

#include <kripto/block/simon128.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint64_t *k;
};

#define F(X) ((ROL64(X, 1) & ROL64(X, 8)) ^ ROL64(X, 2))

static void simon128_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint64_t a;
	uint64_t b;
	unsigned int i = 0;

	a = LOAD64B(CU8(pt));
	b = LOAD64B(CU8(pt) + 8);

	while(i < s->rounds)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE64B(a, U8(ct) + 8);
			STORE64B(b, U8(ct));
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE64B(a, U8(ct));
	STORE64B(b, U8(ct) + 8);
}

static void simon128_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint64_t a;
	uint64_t b;
	unsigned int i = s->rounds;

	a = LOAD64B(CU8(ct));
	b = LOAD64B(CU8(ct) + 8);

	while(i)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE64B(a, U8(pt) + 8);
			STORE64B(b, U8(pt));
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE64B(a, U8(pt));
	STORE64B(b, U8(pt) + 8);
}

static const uint64_t z[3] =
{
	0x3369F885192C0EF5,
	0x3C2CE51207A635DB,
	0x3DC94C3A046D678B
};

static void simon128_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	unsigned int m;
	uint64_t t;

	m = (len + 7) >> 3;
	if(m < 2) m = 2;

	for(i = 0; i < m; i++)
		s->k[i] = 0;

	for(i = 0; i < len; i++)
		s->k[m - 1 - (i >> 3)] |=
			(uint64_t)key[i] << (56 - ((i & 7) << 3));

	for(i = m; i < s->rounds; i++)
	{
		t = ROR64(s->k[i - 1], 3);
		if(m == 4) t ^= s->k[i - 3];
		t ^= ROR64(t, 1) ^ ~s->k[i - m] ^ 3;
		s->k[i] = t ^ ((z[m - 2] >> ((i - m) % 62)) & 1);
	}

	kripto_memwipe(&t, sizeof(uint64_t));
}

static kripto_block *simon128_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r)
	{
		switch((key_len + 7) >> 3)
		{
			case 3: r = 69; break;
			case 4: r = 72; break;
			default: r = 68; break;
		}
	}

	s = malloc(sizeof(kripto_block) + (r << 3));
	if(!s) return 0;

	s->obj.desc = kripto_block_simon128;
	s->size = sizeof(kripto_block) + (r << 3);
	s->k = (uint64_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	simon128_setup(s, key, key_len);

	return s;
}

static void simon128_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *simon128_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r)
	{
		switch((key_len + 7) >> 3)
		{
			case 3: r = 69; break;
			case 4: r = 72; break;
			default: r = 68; break;
		}
	}

	if(sizeof(kripto_block) + (r << 3) > s->size)
	{
		simon128_destroy(s);
		s = simon128_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		simon128_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon128 =
{
	&simon128_create,
	&simon128_recreate,
	0,
	&simon128_encrypt,
	&simon128_decrypt,
	&simon128_destroy,
	"Simon128",
	16, /* block size */
	32 /* max key */
};

const kripto_block_desc *const kripto_block_simon128 = &simon128;
