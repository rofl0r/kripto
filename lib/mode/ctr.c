/*
 * Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
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
#include <kripto/mode.h>
#include <kripto/mode_struct.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/mode/ctr.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
	const kripto_block *block;
	unsigned int block_size;
	uint8_t *x;
	uint8_t *buf;
	unsigned int used;
};

static size_t ctr_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	const size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->block_size)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->block_size - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}

	return i;
}

static size_t ctr_prng
(
	kripto_stream *s,
	void *out,
	const size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->block_size)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->block_size - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = s->buf[s->used++];
	}

	return i;
}

static void ctr_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(struct kripto_stream)
		+ (s->block_size << 1)
		+ sizeof(struct kripto_stream_desc)
	);
	free(s);
}

static kripto_stream *ctr_create
(
	const kripto_block *block,
	const void *iv,
	const unsigned int iv_len
)
{
	kripto_stream *s;
	kripto_block_desc *b;
	struct kripto_stream_desc *stream;

	if(!block) return 0;

	b = kripto_block_get_desc(block);
	if(!b) return 0;

	s = malloc(sizeof(struct kripto_stream)
		+ (kripto_block_size(b) << 1)
		+ sizeof(struct kripto_stream_desc)
	);

	s->block_size = kripto_block_size(b);

	stream = (struct kripto_stream_desc *)
		((uint8_t *)s + sizeof(struct kripto_stream));

	s->x = (uint8_t *)stream + sizeof(struct kripto_stream_desc);
	s->buf = s->x + s->block_size;

	stream->encrypt = &ctr_crypt;
	stream->decrypt = &ctr_crypt;
	stream->prng = &ctr_prng;
	stream->create = 0;
	stream->destroy = &ctr_destroy;
	stream->max_key = kripto_block_max_key(b);
	stream->max_iv = s->block_size;
	stream->max_rounds = kripto_block_max_rounds(b);
	stream->default_rounds = kripto_block_default_rounds(b);

	s->desc = stream;

	if(iv_len) memcpy(s->x, iv, iv_len);
	memset(s->x + iv_len, 0, s->block_size - iv_len);

	s->used = s->block_size;
	s->block = block;

	return s;
}

static const struct kripto_mode_desc ctr =
{
	&ctr_create,
	&kripto_block_size
};

kripto_mode_desc *const kripto_mode_ctr = &ctr;
