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

#include <kripto/block/rc5.h>

struct kripto_block
{
	struct kripto_block_object obj;
	unsigned int r;
	size_t size;
	uint32_t *k;
};

static void rc5_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	uint32_t a;
	uint32_t b;
	uint32_t x[64];
	const unsigned int ls = (key_len + 3) >> 2;

	for(i = 0; i < ls; i++) x[i] = 0;

	for(j = key_len - 1; j != UINT_MAX; j--)
		x[j >> 2] = (x[j >> 2] << 8) | key[j];

	*s->k = 0xB7E15163;
	for(i = 1; i < ((s->r + 1) << 1); i++)
		s->k[i] = s->k[i - 1] + 0x9E3779B9;

	a = b = i = j = k = 0;
	while(k < (s->r + 1) * 6)
	{
		a = s->k[i] = ROL32_03(s->k[i] + a + b);
		b = x[j] = ROL32(x[j] + a + b, a + b);
		if(++i == ((s->r + 1) << 1)) i = 0;
		if(++j == ls) j = 0;
		k++;
	}

	kripto_memwipe(x, ls << 2);
	kripto_memwipe(&a, sizeof(uint32_t));
	kripto_memwipe(&b, sizeof(uint32_t));
}

static void rc5_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t a;
	uint32_t b;
	unsigned int i = 2;

	a = LOAD32L(CU8(pt));
	b = LOAD32L(CU8(pt) + 4);

	a += s->k[0];
	b += s->k[1];

	while(i <= s->r << 1)
	{
		a ^= b; a = ROL32(a, b) + s->k[i++];
		b ^= a; b = ROL32(b, a) + s->k[i++];
	}

	STORE32L(a, U8(ct));
	STORE32L(b, U8(ct) + 4);
}

static void rc5_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t a;
	uint32_t b;
	unsigned int i = (s->r + 1) << 1;

	a = LOAD32L(CU8(ct));
	b = LOAD32L(CU8(ct) + 4);

	while(i > 2)
	{
		b -= s->k[--i]; b = ROR32(b, a) ^ a;
		a -= s->k[--i]; a = ROR32(a, b) ^ b;
	}

	b -= s->k[1];
	a -= s->k[0];

	STORE32L(a, U8(pt));
	STORE32L(b, U8(pt) + 4);
}

static kripto_block *rc5_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	if(!r) r = 12;

	s = malloc(sizeof(kripto_block) + ((r + 1) << 3));
	if(!s) return 0;

	s->obj.desc = kripto_block_rc5;
	s->size = sizeof(kripto_block) + ((r + 1) << 3);
	s->r = r;
	s->k = (uint32_t *)((uint8_t *)s + sizeof(kripto_block));

	rc5_setup(s, key, key_len);

	return s;
}

static void rc5_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *rc5_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	if(!r) r = 12;

	if(sizeof(kripto_block) + ((r + 1) << 3) > s->size)
	{
		rc5_destroy(s);
		s = rc5_create(r, key, key_len);
	}
	else
	{
		s->r = r;
		rc5_setup(s, key, key_len);
	}

	return s;
}

static const kripto_block_desc rc5 =
{
	&rc5_create,
	&rc5_recreate,
	0,
	&rc5_encrypt,
	&rc5_decrypt,
	&rc5_destroy,
	"RC5",
	8, /* block size */
	255 /* max key */
};

const kripto_block_desc *const kripto_block_rc5 = &rc5;
