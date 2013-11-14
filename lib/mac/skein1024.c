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
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block/threefish1024.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>
#include <kripto/object/mac.h>

#include <kripto/mac/skein1024.h>

struct kripto_mac
{
	struct kripto_mac_object obj;
	kripto_block *block;
	unsigned int r;
	unsigned int i;
	int f;
	uint8_t h[128];
	uint8_t buf[128];
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

static void skein1024_process(kripto_mac *s) 
{
	unsigned int i;

	(void)kripto_block_recreate(s->block, s->r, s->h, 128);
	kripto_block_tweak(s->block, s->tweak, 16);
	kripto_block_encrypt(s->block, s->buf, s->h);

	for(i = 0; i < 128; i++) s->h[i] ^= s->buf[i];
}

static kripto_mac *skein1024_recreate
(
	kripto_mac *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	uint64_t t;
	unsigned int block;

	s->r = r;
	s->i = 0;
	s->f = 0;
	memset(s->h, 0, 128);
	memset(s->tweak, 0, 16);

	t = tag_len << 3;

	/* KEY */
	s->tweak[15] = 0x40; /* type KEY, first */

	while(key_len)
	{
		if(key_len > 128) block = 128;
		else block = key_len;

		memcpy(s->buf, key, block);
		memset(s->buf, 0, 128 - block);

		POS_ADD(s->tweak, block);

		key_len -= block;

		if(!key_len) s->tweak[15] |= 0x80; /* add final */

		skein1024_process(s);

		s->tweak[15] &= 0xBF; /* remove first */
	}

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
	memset(s->buf + 16, 0, 112);
	s->tweak[0] = 32;
	s->tweak[15] = 0xC4; /* type CFG, first, final */
	skein1024_process(s);

	/* MSG */
	s->tweak[0] = 0;
	s->tweak[15] = 0x70; /* type MSG, first */

	return s;
}

static void skein1024_input
(
	kripto_mac *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 128)
		{
			POS_ADD(s->tweak, 128);

			skein1024_process(s);
			s->tweak[15] = 0x30; /* type MSG */
			s->i = 0;
		}
	}
}

static void skein1024_finish(kripto_mac *s)
{
	POS_ADD(s->tweak, s->i);

	memset(s->buf + s->i, 0, 128 - s->i);
	s->tweak[15] |= 0x80; /* add final */
	skein1024_process(s);

	memset(s->buf, 0, 128);
	memset(s->tweak, 0, 12);
	s->tweak[0] = 8; /* 8 byte counter */
	s->tweak[15] = 0xFF; /* type OUT, first, final */
	skein1024_process(s);

	s->i = 0;
	s->f = -1;
}

static void skein1024_tag(kripto_mac *s, void *tag, unsigned int len)
{
	assert(s->i + len <= 128);

	if(!s->f) skein1024_finish(s);

	memcpy(tag, s->h + s->i, len);
	s->i += len;
}

static kripto_mac *skein1024_create
(
	const kripto_mac_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s;

	(void)desc;

	s = malloc(sizeof(kripto_mac));
	if(!s) return 0;

	s->obj.desc = kripto_mac_skein1024;

	s->block = kripto_block_create(kripto_block_threefish1024, r, "", 1);
	if(!s->block)
	{
		free(s);
		return 0;
	}

	(void)skein1024_recreate(s, r, key, key_len, tag_len);

	return s;
}

static void skein1024_destroy(kripto_mac *s)
{
	kripto_block_destroy(s->block);
	kripto_memwipe(s, sizeof(kripto_mac));
	free(s);
}

static const kripto_mac_desc skein1024 =
{
	&skein1024_create,
	&skein1024_recreate,
	&skein1024_input,
	&skein1024_tag,
	&skein1024_destroy,
	128, /* max tag */
	UINT_MAX /* max key */
};

const kripto_mac_desc *const kripto_mac_skein1024 = &skein1024;
