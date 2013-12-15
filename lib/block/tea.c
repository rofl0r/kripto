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
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/tea.h>

struct kripto_block
{
	struct kripto_block_object obj;
	uint32_t c;
	uint32_t k[4];
};

static void tea_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t x0 = LOAD32B(CU8(pt));
	uint32_t x1 = LOAD32B(CU8(pt) + 4);
	uint32_t c;

	for(c = 0; c != s->c;)
	{
		c += 0x9E3779B9;
		x0 += ((x1 << 4) + s->k[0]) ^ (x1 + c) ^ ((x1 >> 5) + s->k[1]);
		x1 += ((x0 << 4) + s->k[2]) ^ (x0 + c) ^ ((x0 >> 5) + s->k[3]);
	}

	STORE32B(x0, U8(ct));
	STORE32B(x1, U8(ct) + 4);
}
 
static void tea_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t x0 = LOAD32B(CU8(ct));
	uint32_t x1 = LOAD32B(CU8(ct) + 4);
	uint32_t c;

	for(c = s->c; c; c -= 0x9E3779B9)
	{
		x1 -= ((x0 << 4) + s->k[2]) ^ (x0 + c) ^ ((x0 >> 5) + s->k[3]);
		x0 -= ((x1 << 4) + s->k[0]) ^ (x1 + c) ^ ((x1 >> 5) + s->k[1]);
	}

	STORE32B(x0, U8(pt));
	STORE32B(x1, U8(pt) + 4);
}

static kripto_block *tea_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	unsigned int i;

	if(r) s->c = 0x9E3779B9 * r;
	else s->c = 0xC6EF3720; /* 0x9E3779B9 * 32 */

	for(i = 0; i < 4; i++) s->k[i] = 0;

	/* big endian */
	for(i = 0; i < key_len; i++)
		s->k[i >> 2] |= CU8(key)[i] << (24 - ((i & 3) << 3));

	return s;
}

static kripto_block *tea_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_tea;

	return tea_recreate(s, r, key, key_len);
}

static void tea_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const kripto_block_desc tea =
{
	&tea_create,
	&tea_recreate,
	0,
	&tea_encrypt,
	&tea_decrypt,
	&tea_destroy,
	8, /* block size */
	16 /* max key */
};

const kripto_block_desc *const kripto_block_tea = &tea;
