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
#include <kripto/mode.h>
#include <kripto/mode_desc.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/mode/cfb.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
	const kripto_block *block;
	unsigned int block_size;
	uint8_t *iv;
};

static size_t cfb_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	const size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i += n)
	{
		kripto_block_encrypt(s->block, s->iv, ct);

		for(n = 0; n < s->block_size; n++)
			s->iv[n] = U8(ct)[n] ^= CU8(pt)[n];

		CPTR_INC(pt, n);
		PTR_INC(ct, n);
	}

	return i;
}

static size_t cfb_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	const size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i += n)
	{
		kripto_block_encrypt(s->block, s->iv, pt);

		for(n = 0; n < s->block_size; n++)
		{
			U8(pt)[n] ^= CU8(ct)[n];
			s->iv[n] = CU8(ct)[n];
		}

		CPTR_INC(ct, n);
		PTR_INC(pt, n);
	}

	return i;
}

static size_t cfb_prng
(
	kripto_stream *s,
	void *out,
	const size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i += n)
	{
		kripto_block_encrypt(s->block, s->iv, out);

		for(n = 0; n < s->block_size; n++)
			s->iv[n] = U8(out)[n];

		PTR_INC(out, n);
	}

	return i;
}

static void cfb_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(kripto_stream)
		+ s->block_size
		+ sizeof(kripto_stream_desc)
	);

	free(s);
}

static kripto_stream *cfb_create
(
	const kripto_block *block,
	const void *iv,
	const unsigned int iv_len
)
{
	kripto_stream *s;
	kripto_block_desc *b;
	struct kripto_stream_desc *stream;

	b = kripto_block_get_desc(block);

	s = malloc(sizeof(kripto_stream)
		+ kripto_block_size(b)
		+ sizeof(kripto_stream_desc)
	);
	if(!s) return 0;

	s->block_size = kripto_block_size(b);

	stream = (struct kripto_stream_desc *)
		((uint8_t *)s + sizeof(kripto_stream));

	s->iv = (uint8_t *)stream + sizeof(kripto_stream_desc);

	stream->encrypt = &cfb_encrypt;
	stream->decrypt = &cfb_decrypt;
	stream->prng = &cfb_prng;
	stream->create = 0;
	stream->destroy = &cfb_destroy;
	stream->max_key = kripto_block_max_key(b);
	stream->max_iv = s->block_size;

	s->desc = stream;

	if(iv_len) memcpy(s->iv, iv, iv_len);
	memset(s->iv + iv_len, 0, s->block_size - iv_len);

	s->block = block;

	return s;
}

static const struct kripto_mode_desc cfb =
{
	&cfb_create,
	&kripto_block_size
};

kripto_mode_desc *const kripto_mode_cfb = &cfb;
