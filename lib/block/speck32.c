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

#include <kripto/block/speck32.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint16_t *k;
};

#define R(A, B, K)					\
{									\
	A = (ROR16_07(A) + B) ^ (K);	\
	B = ROL16_02(B) ^ A;			\
}

#define IR(A, B, K)					\
{									\
	B = ROR16_02(B ^ A);			\
	A = ROL16_07((A ^ (K)) - B);	\
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
	uint16_t k[4] = {0, 0, 0, 0};

	for(i = 0; i < len; i++)
		k[3 - (i >> 1)] |= (uint16_t)key[i] << (8 - ((i & 1) << 3));

	s->k[0] = k[0];

	for(i = 0; i < s->rounds - 1;)
	{
		R(k[(i % 3) + 1], k[0], i);
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
	0, /* tweak */
	&speck32_encrypt,
	&speck32_decrypt,
	&speck32_destroy,
	4, /* block size */
	8, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_speck32 = &speck32;
