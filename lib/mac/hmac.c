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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/mac.h>
#include <kripto/desc/mac.h>
#include <kripto/object/mac.h>

#include <kripto/mac/hmac.h>

struct kripto_mac
{
	struct kripto_mac_object obj;
	kripto_hash *hash;
	size_t size;
	unsigned int r;
	unsigned int blocksize;
	uint8_t *key;
};

static int hmac_init
(
	kripto_mac *s,
	const kripto_hash_desc *hash,
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

	memset(s->key + i, 0x36, s->blocksize - i);

	while(i--) s->key[i] ^= 0x36;

	kripto_hash_input(s->hash, s->key, s->blocksize);

	return 0;
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

	kripto_hash_recreate(s->hash, s->r, len);
	kripto_hash_input(s->hash, s->key, i);
	kripto_hash_input(s->hash, tag, len);
	kripto_hash_output(s->hash, tag, len);
}

static void hmac_destroy(kripto_mac *s)
{
	kripto_hash_destroy(s->hash);

	kripto_memwipe(s, s->size);
	free(s);
}

struct ext
{
	kripto_mac_desc desc;
	const kripto_hash_desc *hash;
};

#define EXT(X) ((const struct ext *)(X))

static kripto_mac *hmac_create
(
	const kripto_mac_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	kripto_mac *s;

	s = malloc(sizeof(kripto_mac) + kripto_hash_blocksize(EXT(desc)->hash));
	if(!s) return 0;

	s->key = (uint8_t *)s + sizeof(kripto_mac);

	s->obj.desc = desc;
	s->size = sizeof(kripto_mac) + kripto_hash_blocksize(EXT(desc)->hash);
	s->r = r;
	s->hash = kripto_hash_create(EXT(desc)->hash, r, tag_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	if(hmac_init(s, EXT(desc)->hash, key, key_len, tag_len))
	{
		hmac_destroy(s);
		return 0;
	}

	return s;
}

static kripto_mac *hmac_recreate
(
	kripto_mac *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	s->hash = kripto_hash_recreate(s->hash, r, tag_len);
	if(!s->hash)
	{
		kripto_memwipe(s, s->size);
		free(s);
		return 0;
	}

	s->r = r;

	if(hmac_init(s, EXT(s->obj.desc)->hash, key, key_len, tag_len))
	{
		hmac_destroy(s);
		return 0;
	}

	return s;
}

kripto_mac_desc *kripto_mac_hmac(const kripto_hash_desc *hash)
{
	struct ext *s;

	s = malloc(sizeof(struct ext));
	if(!s) return 0;

	s->hash = hash;

	s->desc.create = &hmac_create;
	s->desc.recreate = &hmac_recreate;
	s->desc.input = &hmac_input;
	s->desc.tag = &hmac_tag;
	s->desc.destroy = &hmac_destroy;
	s->desc.maxtag = kripto_hash_maxout(hash);
	s->desc.maxkey = UINT_MAX;

	return (kripto_mac_desc *)s;
}
