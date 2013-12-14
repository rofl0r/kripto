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

#include <kripto/block/speck64.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define R(A, B, K)					\
{									\
	A = (ROR32_08(A) + B) ^ (K);	\
	B = ROL32_03(B) ^ A;			\
}

#define IR(A, B, K)					\
{									\
	B = ROR32_03(B ^ A);			\
	A = ROL32_08((A ^ (K)) - B);	\
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

	if(len > 12) m = 3;
	else m = 2;

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

	s->obj.desc = kripto_block_speck64;
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
	"Speck64",
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_speck64 = &speck64;
