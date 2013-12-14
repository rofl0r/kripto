/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
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

#include <kripto/block/simon64.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define F(X) ((ROL32_01(X) & ROL32_08(X)) ^ ROL32_02(X))

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
		t = ROR32_03(s->k[i - 1]);
		if(m == 4) t ^= s->k[i - 3];
		t ^= ROR32_01(t) ^ ~s->k[i - m] ^ 3;
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

	s->obj.desc = kripto_block_simon64;
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
	"Simon64",
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_simon64 = &simon64;
