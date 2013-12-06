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

#include <kripto/block/simon32.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint16_t *k;
};

#define F(X) ((ROL16(X, 1) & ROL16(X, 8)) ^ ROL16(X, 2))

static void simon32_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint16_t a;
	uint16_t b;
	unsigned int i = 0;

	a = LOAD16B(CU8(pt));
	b = LOAD16B(CU8(pt) + 2);

	while(i < s->rounds)
	{
		b ^= F(a) ^ s->k[i++];

		if(i == s->rounds)
		{
			STORE16B(a, U8(ct) + 2);
			STORE16B(b, U8(ct));
			return;
		}

		a ^= F(b) ^ s->k[i++];
	}

	STORE16B(a, U8(ct));
	STORE16B(b, U8(ct) + 2);
}

static void simon32_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint16_t a;
	uint16_t b;
	unsigned int i = s->rounds;

	a = LOAD16B(CU8(ct));
	b = LOAD16B(CU8(ct) + 2);

	while(i)
	{
		a ^= F(b) ^ s->k[--i];

		if(!i)
		{
			STORE16B(a, U8(pt) + 2);
			STORE16B(b, U8(pt));
			return;
		}

		b ^= F(a) ^ s->k[--i];
	}

	STORE16B(a, U8(pt));
	STORE16B(b, U8(pt) + 2);
}

static void simon32_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	unsigned int i;
	uint16_t t;

	for(i = 0; i < 4; i++)
		s->k[i] = 0;

	for(i = 0; i < len; i++)
		s->k[3 - (i >> 1)] |=
			(uint16_t)key[i] << (8 - ((i & 1) << 3));

	for(i = 4; i < s->rounds; i++)
	{
		t = ROR16(s->k[i - 1], 3) ^ s->k[i - 3];
		t ^= ROR16(t, 1) ^ ~s->k[i - 4] ^ 3;
		s->k[i] = t ^ ((0x19C3522FB386A45F >> ((i - 4) % 62)) & 1);
	}

	kripto_memwipe(&t, sizeof(uint16_t));
}

static kripto_block *simon32_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 32;

	s = malloc(sizeof(kripto_block) + (r << 1));
	if(!s) return 0;

	s->obj.desc = kripto_block_simon32;
	s->size = sizeof(kripto_block) + (r << 1);
	s->k = (uint16_t *)(((uint8_t *)s) + sizeof(kripto_block));
	s->rounds = r;

	simon32_setup(s, key, key_len);

	return s;
}

static void simon32_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *simon32_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 32;

	if(sizeof(kripto_block) + (r << 1) > s->size)
	{
		simon32_destroy(s);
		s = simon32_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		simon32_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc simon32 =
{
	&simon32_create,
	&simon32_recreate,
	0,
	&simon32_encrypt,
	&simon32_decrypt,
	&simon32_destroy,
	"Simon32",
	4, /* block size */
	8 /* max key */
};

const kripto_block_desc *const kripto_block_simon32 = &simon32;
