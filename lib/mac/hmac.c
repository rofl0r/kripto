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
	uint8_t *key;
};

static int hmac_init
(
	kripto_mac *s,
	void *hash,
	const void *key,
	const unsigned int key_len
)
{
	unsigned int i;
	kripto_hash_desc *hash_desc = kripto_hash_get_desc(hash);

	s->desc = kripto_mac_hmac;
	s->hash = hash;

	if(key_len > kripto_hash_blocksize(hash_desc))
	{
		if(kripto_hash_all(
			hash_desc,
			0,
			key,
			key_len,
			s->key,
			kripto_hash_blocksize(hash_desc))
		) return -1;

		i = kripto_hash_blocksize(hash_desc);
	}
	else
	{
		memcpy(s->key, key, key_len);
		i = key_len;
	}

	memset(s->key, 0, kripto_hash_blocksize(hash_desc) - i);

	for(i = 0; i < kripto_hash_blocksize(hash_desc); i++)
		s->key[i] ^= 0x36;

	kripto_hash_input(hash, s->key, i);

	return 0;
}

static void hmac_destroy(kripto_mac *s)
{
	kripto_memwipe(s,
		kripto_hash_blocksize(kripto_hash_get_desc(s->hash))
		+ sizeof(struct kripto_mac));

	free(s);
}

static kripto_mac *hmac_create
(
	void *hash,
	const void *key,
	const unsigned int key_len
)
{
	kripto_mac *s;

	s = malloc(sizeof(struct kripto_mac)
		+ kripto_hash_blocksize(kripto_hash_get_desc(hash)));
	if(!s) return 0;

	s->key = (uint8_t *)s + sizeof(struct kripto_mac);

	if(hmac_init(s, hash, key, key_len))
	{
		hmac_destroy(s);
		return 0;
	}

	return s;
}

static void hmac_update(kripto_mac *s, const void *in, const size_t len)
{
	kripto_hash_input(s->hash, in, len);
}

static void hmac_finish(kripto_mac *s, void *out, const size_t len)
{
	unsigned int i;

	for(i = 0; i < kripto_hash_blocksize(kripto_hash_get_desc(s->hash)); i++)
		s->key[i] ^= 0x6A; /* 0x5C ^ 0x36 */

	kripto_hash_input(s->hash, s->key, i);
	kripto_hash_finish(s->hash);
	kripto_hash_output(s->hash, out, len);
}

static unsigned int hmac_max_output(const void *hash)
{
	return kripto_hash_max_output(kripto_hash_get_desc(hash));
}

static const struct kripto_mac_desc hmac =
{
	&hmac_create,
	&hmac_update,
	&hmac_finish,
	&hmac_destroy,
	&hmac_max_output
};

kripto_mac_desc *const kripto_mac_hmac = &hmac;
