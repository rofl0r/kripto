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
#include <assert.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/mode.h>
#include <kripto/mode_struct.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/mode/ecb.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
	const kripto_block *block;
	unsigned int block_size;
};

static size_t ecb_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	const size_t len
)
{
	size_t i;

	if(len & (s->block_size - 1)) return 0;

	for(i = 0; i < len; i += s->block_size)
		kripto_block_encrypt(s->block, CU8(pt) + i, U8(ct) + i);

	return i;
}

static size_t ecb_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	const size_t len
)
{
	size_t i;

	if(len & (s->block_size - 1)) return 0;

	for(i = 0; i < len; i += s->block_size)
		kripto_block_decrypt(s->block, CU8(ct) + i, U8(pt) + i);

	return i;
}

static void ecb_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(kripto_stream)
		+ s->block_size
		+ sizeof(kripto_stream_desc)
	);
	free(s);
}

static unsigned int ecb_max_iv(kripto_block_desc *desc)
{
	(void)desc;

	return 0;
}

static kripto_stream *ecb_create
(
	const kripto_block *block,
	const void *iv,
	const unsigned int iv_len
)
{
	kripto_stream *s;
	kripto_block_desc *b;
	struct kripto_stream_desc *stream;

	(void)iv;
	(void)iv_len;
	assert(block);
	assert(!iv_len);

	b = kripto_block_get_desc(block);

	s = malloc(sizeof(kripto_stream)
		+ sizeof(kripto_stream_desc)
	);

	s->block_size = kripto_block_size(b);

	stream = (struct kripto_stream_desc *)
		((uint8_t *)s + sizeof(kripto_stream));

	stream->encrypt = &ecb_encrypt;
	stream->decrypt = &ecb_decrypt;
	stream->prng = 0;
	stream->create = 0;
	stream->destroy = &ecb_destroy;
	stream->max_key = kripto_block_max_key(b);
	stream->max_iv = 0;

	s->desc = stream;
	s->block = block;

	return s;
}

static const kripto_mode_desc ecb =
{
	&ecb_create,
	&ecb_max_iv
};

kripto_mode_desc *const kripto_mode_ecb = &ecb;
