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

#include <kripto/stream/cfb.h>

struct kripto_stream
{
	struct kripto_stream_object obj;
	kripto_block *block;
	uint8_t *prev;
	unsigned int blocksize;
	unsigned int used;
};

static void cfb_encrypt
(
	kripto_stream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->prev, s->prev);
			s->used = 0;
		}

		U8(ct)[i] = s->prev[s->used++] ^= CU8(pt)[i];
	}
}

static void cfb_decrypt
(
	kripto_stream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->prev, pt);
			s->used = 0;
		}

		U8(pt)[i] ^= CU8(ct)[i];
		s->prev[s->used++] = CU8(ct)[i];
	}
}

static void cfb_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == s->blocksize)
		{
			kripto_block_encrypt(s->block, s->prev, s->prev);
			s->used = 0;
		}

		U8(out)[i] = s->prev[s->used++];
	}
}

static void cfb_destroy(kripto_stream *s)
{
	kripto_block_destroy(s->block);
	kripto_memwipe(s, sizeof(kripto_stream) + s->blocksize);
	free(s);
}

struct ext
{
	kripto_stream_desc desc;
	const kripto_block_desc *block;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_stream *cfb_create
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

	s = malloc(sizeof(kripto_stream) + desc->maxiv);
	if(!s) return 0;

	s->obj.desc = desc;
	s->obj.multof = 1;

	s->used = s->blocksize = desc->maxiv;

	s->prev = (uint8_t *)s + sizeof(kripto_stream);

	/* block cipher */
	s->block = kripto_block_create(EXT(desc)->block, rounds, key, key_len);
	if(!s->block)
	{
		kripto_memwipe(s, sizeof(kripto_stream) + s->blocksize);
		free(s);
		return 0;
	}

	/* IV */
	if(iv_len) memcpy(s->prev, iv, iv_len);
	memset(s->prev + iv_len, 0, s->blocksize - iv_len);

	return s;
}

static kripto_stream *cfb_recreate
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
		kripto_memwipe(s, sizeof(kripto_stream) + s->blocksize);
		free(s);
		return 0;
	}

	/* IV */
	if(iv_len) memcpy(s->prev, iv, iv_len);
	memset(s->prev + iv_len, 0, s->blocksize - iv_len);

	s->used = s->blocksize;

	return s;
}

kripto_stream_desc *kripto_stream_cfb(const kripto_block_desc *block)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->block = block;

	s->desc.create = &cfb_create;
	s->desc.recreate = &cfb_recreate;
	s->desc.encrypt = &cfb_encrypt;
	s->desc.decrypt = &cfb_decrypt;
	s->desc.prng = &cfb_prng;
	s->desc.destroy = &cfb_destroy;
	s->desc.maxkey = kripto_block_maxkey(block);
	s->desc.maxiv = kripto_block_size(block);

	return (kripto_stream_desc *)s;
}
