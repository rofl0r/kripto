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

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>
#include <kripto/object/stream.h>

#include <kripto/stream/ecb.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	kripto_block *block;
	unsigned int blocksize;
};

static void ecb_encrypt
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
}

static void ecb_decrypt
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

#define EXT(X) ((const struct ext *)(X))

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

	s->blocksize = kripto_block_size(EXT(desc)->block);

	s->obj.desc = desc;
	s->obj.multof = s->blocksize;

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memwipe(s, sizeof(kripto_stream));
		free(s);
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
		kripto_memwipe(s, sizeof(kripto_stream));
		free(s);
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
