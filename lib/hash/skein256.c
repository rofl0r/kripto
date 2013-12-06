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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block/threefish256.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>
#include <kripto/object/hash.h>

#include <kripto/hash/skein256.h>

struct kripto_hash
{
	struct kripto_hash_object obj;
	kripto_block *block;
	unsigned int r;
	unsigned int i;
	int f;
	uint8_t h[32];
	uint8_t buf[32];
	uint8_t tweak[16];
};

#define POS_ADD(TWEAK, ADD)	\
{							\
	TWEAK[0] += ADD;		\
	if(!TWEAK[0])			\
	if(!++TWEAK[1])			\
	if(!++TWEAK[2])			\
	if(!++TWEAK[3])			\
	if(!++TWEAK[4])			\
	if(!++TWEAK[5])			\
	if(!++TWEAK[6])			\
	if(!++TWEAK[7])			\
	if(!++TWEAK[8])			\
	if(!++TWEAK[9])			\
	if(!++TWEAK[10])		\
	{						\
		TWEAK[11]++;		\
		assert(TWEAK[11]);	\
	}						\
}

static void skein256_process(kripto_hash *s) 
{
	unsigned int i;

	(void)kripto_block_recreate(s->block, s->r, s->h, 32);
	kripto_block_tweak(s->block, s->tweak, 16);
	kripto_block_encrypt(s->block, s->buf, s->h);

	for(i = 0; i < 32; i++) s->h[i] ^= s->buf[i];
}

static kripto_hash *skein256_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	uint64_t t;

	s->r = r;
	s->i = 0;
	s->f = 0;
	memset(s->h, 0, 32);
	memset(s->tweak, 0, 16);

	t = len << 3;

	/* CFG */
	s->buf[0] = 'S';
	s->buf[1] = 'H';
	s->buf[2] = 'A';
	s->buf[3] = '3';
	s->buf[4] = 1;
	s->buf[5] = 0;
	s->buf[6] = 0;
	s->buf[7] = 0;
	STORE64L(t, s->buf + 8);
	memset(s->buf + 16, 0, 16);
	s->tweak[0] = 32;
	s->tweak[15] = 0xC4; /* type CFG, first, final */
	skein256_process(s);

	/* MSG */
	s->tweak[0] = 0;
	s->tweak[15] = 0x70; /* type MSG, first */

	return s;
}

static void skein256_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 32)
		{
			POS_ADD(s->tweak, 32);

			skein256_process(s);
			s->tweak[15] = 0x30; /* type MSG */
			s->i = 0;
		}
	}
}

static void skein256_finish(kripto_hash *s)
{
	POS_ADD(s->tweak, s->i);

	memset(s->buf + s->i, 0, 32 - s->i);
	s->tweak[15] |= 0x80; /* add final */
	skein256_process(s);

	memset(s->buf, 0, 32);
	memset(s->tweak, 0, 12);
	s->tweak[0] = 8; /* 8 byte counter */
	s->tweak[15] = 0xFF; /* type OUT, first, final */
	skein256_process(s);

	s->i = 0;
	s->f = -1;
}

static void skein256_output(kripto_hash *s, void *out, size_t len)
{
	assert(s->i + len <= 32);

	if(!s->f) skein256_finish(s);

	memcpy(out, s->h + s->i, len);
	s->i += len;
}

static kripto_hash *skein256_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->obj.desc = kripto_hash_skein256;

	s->block = kripto_block_create(kripto_block_threefish256, r, "", 1);
	if(!s->block)
	{
		free(s);
		return 0;
	}

	(void)skein256_recreate(s, r, len);

	return s;
}

static void skein256_destroy(kripto_hash *s)
{
	kripto_block_destroy(s->block);
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int skein256_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	s.block = kripto_block_create(kripto_block_threefish256, r, "", 1);
	if(!s.block) return -1;

	(void)skein256_recreate(&s, r, out_len);
	skein256_input(&s, in, in_len);
	skein256_output(&s, out, out_len);

	kripto_block_destroy(s.block);
	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc skein256 =
{
	&skein256_create,
	&skein256_recreate,
	&skein256_input,
	&skein256_output,
	&skein256_destroy,
	&skein256_hash,
	32, /* max output */
	32 /* block_size */
};

const kripto_hash_desc *const kripto_hash_skein256 = &skein256;
