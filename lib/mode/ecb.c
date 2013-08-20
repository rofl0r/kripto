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

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/mode/ecb.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
	kripto_block *block;
	unsigned int blocksize;
};

static size_t ecb_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i += s->blocksize)
		kripto_block_encrypt(s->block, CU8(pt) + i, U8(ct) + i);

	return i;
}

static size_t ecb_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i += s->blocksize)
		kripto_block_decrypt(s->block, CU8(ct) + i, U8(pt) + i);

	return i;
}

static void ecb_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memwipe(s, sizeof(kripto_stream));
	free(s);
}

struct ext
{
	kripto_stream_desc desc;
	const kripto_block_desc *block;
};

#define EXT(X) ((struct ext *)(X))

static kripto_stream *ecb_create
(
	const kripto_stream_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s;

	(void)iv;
	(void)iv_len;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

	s->desc = desc;

	s->blocksize = kripto_block_size(EXT(s)->block);

	/* block cipher */
	s->block = kripto_block_create(EXT(s)->block, rounds, key, key_len);
	if(!s->block)
	{
		ecb_destroy(s);
		return 0;
	}

	return s;
}

static kripto_stream *ecb_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	(void)iv;
	(void)iv_len;

	/* block cipher */
	s->block = kripto_block_recreate(s->block, rounds, key, key_len);
	if(!s->block)
	{
		ecb_destroy(s);
		return 0;
	}

	return s;
}

kripto_stream_desc *kripto_stream_ecb(const kripto_block_desc *block)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &ecb_create;
	s->desc.recreate = &ecb_recreate;
	s->desc.encrypt = &ecb_encrypt;
	s->desc.decrypt = &ecb_decrypt;
	s->desc.prng = 0;
	s->desc.destroy = &ecb_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = 0;

	return (kripto_stream_desc *)s;
}
