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

#include <kripto/stream/cbc.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
	kripto_block *block;
	unsigned int blocksize;
	uint8_t *iv;
	uint8_t *buf;
};

static void cbc_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i += n)
	{
		for(n = 0; n < s->blocksize; n++)
			U8(ct)[n] = CU8(pt)[n] ^ s->iv[n];

		kripto_block_encrypt(s->block, ct, ct);

		for(n = 0; n < s->blocksize; n++)
			s->iv[n] = U8(ct)[n];

		CPTR_INC(pt, n);
		PTR_INC(ct, n);
	}
}

static void cbc_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	size_t i;
	unsigned int n;

	for(i = 0; i < len; i += n)
	{
		for(n = 0; n < s->blocksize; n++)
			s->buf[n] = CU8(ct)[n];

		kripto_block_decrypt(s->block, ct, pt);

		for(n = 0; n < s->blocksize; n++)
		{
			U8(pt)[n] ^=  s->iv[n];
			s->iv[n] = s->buf[n];
		}

		CPTR_INC(ct, n);
		PTR_INC(pt, n);
	}
}

static void cbc_destroy(kripto_stream *s)
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

#define EXT(X) ((struct ext *)(X))

static kripto_stream *cbc_create
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

	s->blocksize = desc->maxiv;

	s->iv = (uint8_t *)s + sizeof(kripto_stream);
	s->buf = s->iv + s->blocksize;

	/* block cipher */
	s->block = kripto_block_create(EXT(s)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memwipe(s, sizeof(kripto_stream) + (s->blocksize << 1));
		free(s);
		return 0;
	}

	/* IV */
	if(iv_len) memcpy(s->iv, iv, iv_len);
	memset(s->iv + iv_len, 0, s->blocksize - iv_len);

	return s;
}

static kripto_stream *cbc_recreate
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

	/* IV */
	if(iv_len) memcpy(s->iv, iv, iv_len);
	memset(s->iv + iv_len, 0, s->blocksize - iv_len);

	return s;
}

kripto_stream_desc *kripto_stream_cbc(const kripto_block_desc *block)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &cbc_create;
	s->desc.recreate = &cbc_recreate;
	s->desc.encrypt = &cbc_encrypt;
	s->desc.decrypt = &cbc_decrypt;
	s->desc.prng = 0;
	s->desc.destroy = &cbc_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);

	return (kripto_stream_desc *)s;
}
