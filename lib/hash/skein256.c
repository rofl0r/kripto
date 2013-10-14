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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block/threefish256.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>

#include <kripto/hash/skein256.h>

struct kripto_hash
{
	const kripto_hash_desc *hash;
	kripto_block *block;
	unsigned int r;
	unsigned int i;
	int f;
	uint8_t h[32];
	uint8_t buf[32];
	uint8_t tweak[16];
};

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

	t = len << 3;

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

	memset(s->tweak, 0, 16);
	s->tweak[0] = 32;
	s->tweak[15] = 0xC4; /* type CFG, first, final */
	skein256_process(s);

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
			s->tweak[0] += 32;
			if(!s->tweak[0])
			if(!++s->tweak[1])
			if(!++s->tweak[2])
			if(!++s->tweak[3])
			if(!++s->tweak[4])
			if(!++s->tweak[5])
			if(!++s->tweak[6])
			if(!++s->tweak[7])
			if(!++s->tweak[8])
			if(!++s->tweak[9])
			if(!++s->tweak[10])
			{
				s->tweak[11]++;
				assert(s->tweak[11]);
			}

			skein256_process(s);
			s->tweak[15] = 0x30; /* type MSG */
			s->i = 0;
		}
	}
}

static void skein256_finish(kripto_hash *s)
{
	s->tweak[0] += s->i;
	if(!s->tweak[0])
	if(!++s->tweak[1])
	if(!++s->tweak[2])
	if(!++s->tweak[3])
	if(!++s->tweak[4])
	if(!++s->tweak[5])
	if(!++s->tweak[6])
	if(!++s->tweak[7])
	if(!++s->tweak[8])
	if(!++s->tweak[9])
	if(!++s->tweak[10])
	{
		s->tweak[11]++;
		assert(s->tweak[11]);
	}

	memset(s->buf + s->i, 0, 32 - s->i);

	if(s->tweak[15] == 0x70) /* if still first */
		s->tweak[15] = 0xF0; /* type MSG, first, final */
	else s->tweak[15] = 0xB0; /* type MSG, final */

	skein256_process(s);

	memset(s->buf, 0, 32);
	memset(s->tweak, 0, 12);
	s->tweak[0] = 0x8;
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

	s->hash = kripto_hash_skein256;

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
