/*
 * Copyright (C) 2011, 2013 Gregor Pintar <grpintar@gmail.com>
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
#include <kripto/desc/stream.h>

#include <kripto/stream/ctr.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
	kripto_block *block;
	uint8_t *x;
	uint8_t *buf;
	unsigned int blocksize;
	unsigned int used;
};

static void ctr_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->blocksize - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}
}

static void ctr_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->x, s->buf);
			s->used = 0;

			for(n = s->blocksize - 1; n; n--)
				if(++s->x[n]) break;
		}

		U8(out)[i] = s->buf[s->used++];
	}
}

static void ctr_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memwipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
	free(s);
}

struct ext
{
	kripto_stream_desc desc;
	const kripto_block_desc *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_stream *ctr_create
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

	s = malloc(sizeof(kripto_stream) + (desc->maxiv << 1));
	if(!s) return 0;

	s->desc = desc;

	s->used = s->blocksize = desc->maxiv;

	s->x = (uint8_t *)s + sizeof(kripto_stream);
	s->buf = s->x + s->blocksize;

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memwipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
		free(s);
		return 0;
	}

	/* IV (nonce) */
	if(iv_len) memcpy(s->x, iv, iv_len);
	memset(s->x + iv_len, 0, s->blocksize - iv_len);

	return s;
}

static kripto_stream *ctr_recreate
(
	kripto_stream *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	/* block cipher */
	s->block = kripto_block_recreate(s->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memwipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
		free(s);
		return 0;
	}

	/* IV (nonce) */
	if(iv_len) memcpy(s->x, iv, iv_len);
	memset(s->x + iv_len, 0, s->blocksize - iv_len);

	s->used = s->blocksize;

	return s;
}

kripto_stream_desc *kripto_stream_ctr(const kripto_block_desc *block)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &ctr_create;
	s->desc.recreate = &ctr_recreate;
	s->desc.encrypt = &ctr_crypt;
	s->desc.decrypt = &ctr_crypt;
	s->desc.prng = &ctr_prng;
	s->desc.destroy = &ctr_destroy;
	s->desc.multof = 1;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);

	return (kripto_stream_desc *)s;
}
