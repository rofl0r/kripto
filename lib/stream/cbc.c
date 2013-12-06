/*
 * Written in 2011 by Gregor Pintar <grpintar@gmail.com>
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

#include <kripto/stream/cbc.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
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

		pt = CU8(pt) + n;
		ct = U8(ct) + n;
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

		ct = CU8(ct) + n;
		pt = U8(pt) + n;
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

#define EXT(X) ((const struct ext *)(X))

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

	s->obj.desc = desc;
	s->obj.multof = s->blocksize;

	s->blocksize = desc->maxiv;

	s->iv = (uint8_t *)s + sizeof(kripto_stream);
	s->buf = s->iv + s->blocksize;

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
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
