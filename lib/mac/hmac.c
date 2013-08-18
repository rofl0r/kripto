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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <kripto/memwipe.h>
#include <kripto/mac.h>
#include <kripto/mac_desc.h>
#include <kripto/hash.h>

#include <kripto/mac/hmac.h>

struct kripto_mac
{
	kripto_mac_desc *desc;
	kripto_hash *hash;
	size_t size;
	unsigned int r;
	unsigned int blocksize;
	uint8_t *key;
};

static int hmac_init
(
	kripto_mac *s,
	kripto_hash_desc *hash,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	unsigned int i;

	s->blocksize = kripto_hash_blocksize(hash);

	if(key_len > s->blocksize)
	{
		if(kripto_hash_all(
			hash,
			s->r,
			key,
			key_len,
			s->key,
			tag_len)
		) return -1;

		i = tag_len;
	}
	else
	{
		memcpy(s->key, key, key_len);
		i = key_len;
	}

	memset(s->key + i, 0, s->blocksize - i);

	for(i = 0; i < s->blocksize; i++)
		s->key[i] ^= 0x36;

	kripto_hash_input(s->hash, s->key, i);

	return 0;
}

static void hmac_destroy(kripto_mac *s)
{
	kripto_hash_destroy(s->hash);

	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_mac *hmac_create
(
	const void *hash,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s;

	s = malloc(sizeof(kripto_mac) + kripto_hash_blocksize(hash));
	if(!s) return 0;

	s->key = (uint8_t *)s + sizeof(kripto_mac);

	s->desc = kripto_mac_hmac;
	s->size = sizeof(kripto_mac) + kripto_hash_blocksize(hash);
	s->r = r;
	s->hash = kripto_hash_create(hash, tag_len, r);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	if(hmac_init(s, hash, key, key_len, tag_len))
	{
		hmac_destroy(s);
		return 0;
	}

	return s;
}

static kripto_mac *hmac_recreate
(
	kripto_mac *s,
	const void *hash,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	if(sizeof(kripto_mac) + kripto_hash_blocksize(hash) > s->size)
	{
		hmac_destroy(s);
		s = hmac_create(hash, r, key, key_len, tag_len);
	}
	else
	{
		if(hash == kripto_hash_get_desc(s->hash))
			s->hash = kripto_hash_recreate(s->hash, tag_len, r);
		else
		{
			kripto_hash_destroy(s->hash);
			s->hash = kripto_hash_create(hash, tag_len, r);
			if(!s->hash)
			{
				hmac_destroy(s);
				return 0;
			}
		}

		s->r = r;
		if(hmac_init(s, hash, key, key_len, tag_len))
		{
			hmac_destroy(s);
			return 0;
		}
	}

	return s;
}

static void hmac_input(kripto_mac *s, const void *in, size_t len)
{
	kripto_hash_input(s->hash, in, len);
}

static void hmac_tag(kripto_mac *s, void *tag, unsigned int len)
{
	unsigned int i;

	for(i = 0; i < s->blocksize; i++)
		s->key[i] ^= 0x6A; /* 0x5C ^ 0x36 */

	kripto_hash_output(s->hash, tag, len);

	kripto_hash_recreate(s->hash, len, s->r);
	kripto_hash_input(s->hash, s->key, i);
	kripto_hash_input(s->hash, tag, len);
	kripto_hash_output(s->hash, tag, len);
}

static unsigned int hmac_max_tag(const void *hash)
{
	return kripto_hash_max_output(hash);
}

static const struct kripto_mac_desc hmac =
{
	&hmac_create,
	&hmac_recreate,
	&hmac_input,
	&hmac_tag,
	&hmac_destroy,
	&hmac_max_tag
};

kripto_mac_desc *const kripto_mac_hmac = &hmac;
