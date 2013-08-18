/*
 * Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
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
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/stream/rc4.h>
#include <kripto/stream/rc4i.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
	uint8_t p[256];
	uint8_t i;
	uint8_t j;
};

#define RC4_DEFAULT_ROUNDS 0
#define RC4I_DEFAULT_ROUNDS 512
#define RC4I_MAX_KEY 256
#define RC4I_MAX_IV 256

static void improved_setup
(
	kripto_stream *s,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int rounds
)
{
	unsigned int i;
	unsigned int j;
	uint8_t t;

	s->i = s->j = 0;

	for(i = 0; i < 256; i++) s->p[i] = i;

	/* key */
	if(key && key_len)
	{
		j = 0;
		for(i = 0; i < rounds; i++)
		{
			s->j = s->j + s->p[s->i] + CU8(key)[j++];
			if(j == key_len) j = 0;

			t = s->p[s->i];
			s->p[s->i] = s->p[s->j];
			s->p[s->j] = t;

			s->i++;
		}
	}

	/* iv */
	if(iv && iv_len)
	{
		j = 0;
		for(i = 0; i < rounds; i++)
		{
			s->j = s->j + s->p[s->i] + CU8(iv)[j++];
			if(j == iv_len) j = 0;

			t = s->p[s->i];
			s->p[s->i] = s->p[s->j];
			s->p[s->j] = t;

			s->i++;
		}

		/* key */
		if(key && key_len)
		{
			j = 0;
			for(i = 0; i < rounds; i++)
			{
				s->j = s->j + s->p[s->i] + CU8(key)[j++];
				if(j == key_len) j = 0;

				t = s->p[s->i];
				s->p[s->i] = s->p[s->j];
				s->p[s->j] = t;

				s->i++;
			}
		}
	}

	s->i = s->j; /* original RC4: s->i = s->j = 0; */
}

static uint8_t rc4(kripto_stream *s)
{
	uint8_t t;

	s->i++;
	s->j = s->j + s->p[s->i];

	t = s->p[s->i];
	s->p[s->i] = s->p[s->j];
	s->p[s->j] = t;

	return(s->p[(uint8_t)(s->p[s->i] + s->p[s->j])]);
}

static size_t rc4_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
		U8(out)[i] = CU8(in)[i] ^ rc4(s);

	return i;
}

static size_t rc4_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
		U8(out)[i] = rc4(s);

	return i;
}

static kripto_stream *rc4i_recreate
(
	kripto_stream *s,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int r
)
{
	unsigned int rounds = r;

	assert(key_len + iv_len <= 256);
	if(!rounds) rounds = 512;

	improved_setup(s, key, key_len, iv, iv_len, r);

	return s;
}

static kripto_stream *rc4_recreate
(
	kripto_stream *s,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int r
)
{
	unsigned int i;

	assert(key_len + iv_len <= 256);

	improved_setup(s, key, key_len, iv, iv_len, 256);

	s->i = s->j = 0;

	/* drop ? */
	for(i = 0; i < r; i++) (void)rc4(s);

	return s;
}

static kripto_stream *rc4i_create
(
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int r
)
{
	kripto_stream *s;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

	s->desc = kripto_stream_rc4i;
	(void)rc4i_recreate(s, key, key_len, iv, iv_len, r);

	return s;
}

static kripto_stream *rc4_create
(
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len,
	unsigned int r
)
{
	kripto_stream *s;
	unsigned int i;

	s = rc4i_create(key, key_len, iv, iv_len, 256);
	if(!s) return 0;

	s->desc = kripto_stream_rc4;

	s->i = s->j = 0;

	/* drop ? */
	for(i = 0; i < r; i++) (void)rc4(s);

	return s;
}

static void rc4_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(kripto_stream));
	free(s);
}

/* RC4 */
static const struct kripto_stream_desc rc4_desc =
{
	&rc4_create,
	&rc4_recreate,
	&rc4_crypt,
	&rc4_crypt,
	&rc4_prng,
	&rc4_destroy,
	256, /* max key */
	0 /* max iv */
};

kripto_stream_desc *const kripto_stream_rc4 = &rc4_desc;

/* RC4i */
static const struct kripto_stream_desc rc4i =
{
	&rc4i_create,
	&rc4i_recreate,
	&rc4_crypt,
	&rc4_crypt,
	&rc4_prng,
	&rc4_destroy,
	256, /* max key */
	256 /* max iv */
};

kripto_stream_desc *const kripto_stream_rc4i = &rc4i;
