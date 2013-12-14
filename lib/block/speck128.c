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

#include <kripto/block/speck128.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
	uint64_t *k;
};

#define R(A, B, K)					\
{									\
	A = (ROR64_08(A) + B) ^ (K);	\
	B = ROL64_03(B) ^ A;			\
}

#define IR(A, B, K)					\
{									\
	B = ROR64_03(B ^ A);			\
	A = ROL64_08((A ^ (K)) - B);	\
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

	if(len > 24) m = 3;
	else if(len > 16) m = 2;
	else m = 1;

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
	"Speck128",
	16, /* block size */
	32 /* max key */
};

const kripto_block_desc *const kripto_block_speck128 = &speck128;
