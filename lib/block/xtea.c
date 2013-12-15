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

/* this XTEA implementation is big endian */

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/xtea.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int rounds;
	size_t size;
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
		k[i >> 2] |= key[i] << (24 - ((i & 3) << 3));

	key_len = (key_len + 3) >> 2;
	i = 0;
	while(i < s->rounds)
	{
		s->k[i++] = c + k[c % key_len];
		if(i == s->rounds) break;
		c += 0x9E3779B9;
		s->k[i++] = c + k[(c >> 11) % key_len];
	}

	kripto_memwipe(k, 16);
}

#define F(X) ((((X) << 4) ^ ((X) >> 5)) + (X))

static void xtea_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = LOAD32B(CU8(pt));
	uint32_t x1 = LOAD32B(CU8(pt) + 4);
	unsigned int i = 0;

	while(i < s->rounds)
	{
		x0 += F(x1) ^ s->k[i++];

		if(i == s->rounds) break;

		x1 += F(x0) ^ s->k[i++];
	}

	STORE32B(x0, U8(ct));
	STORE32B(x1, U8(ct) + 4);
}
 
static void xtea_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = LOAD32B(CU8(ct));
	uint32_t x1 = LOAD32B(CU8(ct) + 4);
	unsigned int i = s->rounds - 1;

	while(i != UINT_MAX)
	{
		x1 -= F(x0) ^ s->k[i--];

		if(i == UINT_MAX) break;

		x0 -= F(x1) ^ s->k[i--];
	}

	STORE32B(x0, U8(pt));
	STORE32B(x1, U8(pt) + 4);
}

static kripto_block *xtea_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 64;

	s = malloc(sizeof(kripto_block) + (r << 2));
	if(!s) return 0;

	s->obj.desc = kripto_block_xtea;
	s->size = sizeof(kripto_block) + (r << 2);
	s->rounds = r;
	s->k = (uint32_t *)((uint8_t *)s + sizeof(kripto_block));

	xtea_setup(s, key, key_len);

	return s;
}

static void xtea_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *xtea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 64;

	if(sizeof(kripto_block) + (r << 2) > s->size)
	{
		xtea_destroy(s);
		s = xtea_create(r, key, key_len);
	}
	else
	{
		s->rounds = r;
		xtea_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc xtea =
{
	&xtea_create,
	&xtea_recreate,
	0,
	&xtea_encrypt,
	&xtea_decrypt,
	&xtea_destroy,
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_xtea = &xtea;
