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
#include <stdlib.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/hash/keccak1600.h>
#include <kripto/hash/keccak800.h>
#include <kripto/authstream.h>
#include <kripto/desc/authstream.h>
#include <kripto/object/authstream.h>

#include <kripto/authstream/keccak1600.h>
#include <kripto/authstream/keccak800.h>

struct kripto_authstream
{
	struct kripto_authstream_object obj;
	kripto_hash *hash;
	unsigned int size;
	uint8_t *buf;
	unsigned int rate;
	unsigned int i;
};

static void keccak_encrypt
(
	kripto_authstream *s,
	const void *pt,
	void *ct,
	size_t len
)
{
	size_t i;
	uint8_t t;

	for(i = 0; i < len; i++)
	{
		if(s->i == s->rate)
		{
			kripto_hash_output(s->hash, s->buf, s->rate);
			s->i = 0;
		}

		t = CU8(pt)[i];
		U8(ct)[i] = t ^ s->buf[s->i++];

		kripto_hash_input(s->hash, &t/*U8(ct) + i*/, 1);
	}
}

static void keccak_decrypt
(
	kripto_authstream *s,
	const void *ct,
	void *pt,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++, s->i++)
	{
		if(s->i == s->rate)
		{
			kripto_hash_output(s->hash, s->buf, s->rate);
			s->i = 0;
		}

		s->buf[s->i] ^= CU8(ct)[i];

		kripto_hash_input(s->hash, s->buf + s->i/*CU8(ct) + i*/, 1);

		U8(pt)[i] = s->buf[s->i];
	}
}

static void keccak_header
(
	kripto_authstream *s,
	const void *header,
	size_t len
)
{
	kripto_hash_input(s->hash, header, len);
}

static void keccak_tag(kripto_authstream *s, void *tag, unsigned int len)
{
	kripto_hash_output(s->hash, tag, len);
}

static void keccak_destroy(kripto_authstream *s)
{
	kripto_hash_destroy(s->hash);
	kripto_memwipe(s, s->size);
	free(s);
}

/* 1600 */
static kripto_authstream *keccak1600_create
(
	const kripto_authstream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	kripto_authstream *s;

	(void)desc;

	s = malloc(sizeof(kripto_authstream) + 200 - (tag_len << 1));
	if(!s) return 0;

	s->obj.desc = kripto_authstream_keccak1600;
	s->obj.multof = 1;

	s->i = s->rate = 200 - (tag_len << 1);
	s->size = sizeof(kripto_authstream) + s->rate;
	s->buf = U8(s) + sizeof(kripto_authstream);

	s->hash = kripto_hash_create(kripto_hash_keccak1600, r, tag_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);
	kripto_hash_input(s->hash, iv, iv_len);

	return s;
}

static kripto_authstream *keccak1600_recreate
(
	kripto_authstream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	if(sizeof(kripto_authstream) + 200 - (tag_len << 1) > s->size)
	{
		keccak_destroy(s);
		s = keccak1600_create(s->obj.desc, r, key, key_len, iv, iv_len, tag_len);
	}
	else
	{
		s->i = s->rate = 200 - (tag_len << 1);

		(void)kripto_hash_recreate(s->hash, r, tag_len);

		kripto_hash_input(s->hash, key, key_len);
		kripto_hash_input(s->hash, iv, iv_len);
	}

	return s;
}

static const kripto_authstream_desc keccak1600 =
{
	&keccak1600_create,
	&keccak1600_recreate,
	&keccak_encrypt,
	&keccak_decrypt,
	&keccak_header,
	&keccak_tag,
	&keccak_destroy,
	UINT_MAX, /* max key */
	UINT_MAX, /* max iv */
	99 /* max tag */
};

const kripto_authstream_desc *const kripto_authstream_keccak1600 = &keccak1600;

/* 800 */
static kripto_authstream *keccak800_create
(
	const kripto_authstream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	kripto_authstream *s;

	(void)desc;

	s = malloc(sizeof(kripto_authstream) + 100 - (tag_len << 1));
	if(!s) return 0;

	s->obj.desc = kripto_authstream_keccak800;
	s->obj.multof = 1;

	s->i = s->rate = 100 - (tag_len << 1);
	s->size = sizeof(kripto_authstream) + s->rate;
	s->buf = U8(s) + sizeof(kripto_authstream);

	s->hash = kripto_hash_create(kripto_hash_keccak800, r, tag_len);
	if(!s->hash)
	{
		free(s);
		return 0;
	}

	kripto_hash_input(s->hash, key, key_len);
	kripto_hash_input(s->hash, iv, iv_len);

	return s;
}

static kripto_authstream *keccak800_recreate
(
	kripto_authstream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int tag_len
)
{
	if(sizeof(kripto_authstream) + 100 - (tag_len << 1) > s->size)
	{
		keccak_destroy(s);
		s = keccak800_create(s->obj.desc, r, key, key_len, iv, iv_len, tag_len);
	}
	else
	{
		s->i = s->rate = 100 - (tag_len << 1);

		(void)kripto_hash_recreate(s->hash, r, tag_len);

		kripto_hash_input(s->hash, key, key_len);
		kripto_hash_input(s->hash, iv, iv_len);
	}

	return s;
}

static const kripto_authstream_desc keccak800 =
{
	&keccak800_create,
	&keccak800_recreate,
	&keccak_encrypt,
	&keccak_decrypt,
	&keccak_header,
	&keccak_tag,
	&keccak_destroy,
	UINT_MAX, /* max key */
	UINT_MAX, /* max iv */
	49 /* max tag */
};

const kripto_authstream_desc *const kripto_authstream_keccak800 = &keccak800;
