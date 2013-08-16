﻿/*
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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/hash_desc.h>

#include <kripto/hash/sha1.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
	uint64_t len;
	uint32_t h[5];
	uint8_t buf[64];
	unsigned int i;
	int o;
};

#define F0(X, Y, Z) (Z ^ (X & (Y ^ Z)))
#define F1(X, Y, Z) (X ^ Y ^ Z)
#define F2(X, Y, Z) ((X & Y) | (Z & (X | Y)))

#define G0(A, B, C, D, E, W)							\
{														\
	E += ROL32(A, 5) + F0(B, C, D) + W + 0x5A827999;	\
	B = ROL32(B, 30);									\
}

#define G1(A, B, C, D, E, W)							\
{														\
	E += ROL32(A, 5) + F1(B, C, D) + W + 0x6ED9EBA1;	\
	B = ROL32(B, 30);									\
}

#define G2(A, B, C, D, E, W)							\
{														\
	E += ROL32(A, 5) + F2(B, C, D) + W + 0x8F1BBCDC;	\
	B = ROL32(B, 30);									\
}

#define G3(A, B, C, D, E, W)							\
{														\
	E += ROL32(A, 5) + F1(B, C, D) + W + 0xCA62C1D6;	\
	B = ROL32(B, 30);									\
}

static kripto_hash *sha1_recreate
(
	kripto_hash *s,
	const size_t len,
	const unsigned int r
)
{
	(void)r;
	(void)len;
	s->len = s->o = s->i = 0;

	s->h[0] = 0x67452301;
	s->h[1] = 0xEFCDAB89;
	s->h[2] = 0x98BADCFE;
	s->h[3] = 0x10325476;
	s->h[4] = 0xC3D2E1F0;

	return s;
}

static void sha1_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t a = s->h[0];
	uint32_t b = s->h[1];
	uint32_t c = s->h[2];
	uint32_t d = s->h[3];
	uint32_t e = s->h[4];
	uint32_t w[80];
	unsigned int i;

	w[0] = U8TO32_BE(data);
	w[1] = U8TO32_BE(data + 4);
	w[2] = U8TO32_BE(data + 8);
	w[3] = U8TO32_BE(data + 12);
	w[4] = U8TO32_BE(data + 16);
	w[5] = U8TO32_BE(data + 20);
	w[6] = U8TO32_BE(data + 24);
	w[7] = U8TO32_BE(data + 28);
	w[8] = U8TO32_BE(data + 32);
	w[9] = U8TO32_BE(data + 36);
	w[10] = U8TO32_BE(data + 40);
	w[11] = U8TO32_BE(data + 44);
	w[12] = U8TO32_BE(data + 48);
	w[13] = U8TO32_BE(data + 52);
	w[14] = U8TO32_BE(data + 56);
	w[15] = U8TO32_BE(data + 60);

	for(i = 16; i < 80; i++)
		w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	for(i = 0; i < 20;)
	{
		G0(a, b, c, d, e, w[i++]);
		G0(e, a, b, c, d, w[i++]);
		G0(d, e, a, b, c, w[i++]);
		G0(c, d, e, a, b, w[i++]);
		G0(b, c, d, e, a, w[i++]);
	}

	while(i < 40)
	{
		G1(a, b, c, d, e, w[i++]);
		G1(e, a, b, c, d, w[i++]);
		G1(d, e, a, b, c, w[i++]);
		G1(c, d, e, a, b, w[i++]);
		G1(b, c, d, e, a, w[i++]);
	}

	while(i < 60)
	{
		G2(a, b, c, d, e, w[i++]);
		G2(e, a, b, c, d, w[i++]);
		G2(d, e, a, b, c, w[i++]);
		G2(c, d, e, a, b, w[i++]);
		G2(b, c, d, e, a, w[i++]);
	}

	while(i < 80)
	{
		G3(a, b, c, d, e, w[i++]);
		G3(e, a, b, c, d, w[i++]);
		G3(d, e, a, b, c, w[i++]);
		G3(c, d, e, a, b, w[i++]);
		G3(b, c, d, e, a, w[i++]);
	}

	kripto_memwipe(w, 80);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
}

static void sha1_input
(
	kripto_hash *s,
	const void *in,
	const size_t len
) 
{
	size_t i;

	s->len += len << 3;
	assert(s->len >= len << 3);

	for(i = 0; i < len; i++)
	{
		s->buf[s->i++] = CU8(in)[i];

		if(s->i == 64)
		{
			sha1_process(s, s->buf);
			s->i = 0;
		}
	}
}

static void sha1_finish(kripto_hash *s)
{
	s->buf[s->i++] = 0x80; /* pad */

	if(s->i > 56) /* not enough space for length */
	{
		while(s->i < 64) s->buf[s->i++] = 0;
		sha1_process(s, s->buf);
		s->i = 0;
	}
	while(s->i < 56) s->buf[s->i++] = 0;

	/* add length */
	//s->len << 3;
	U64TO8_BE(s->len, s->buf + 56);

	sha1_process(s, s->buf);

	s->i = 0;
	s->o = -1;
}

static void sha1_output(kripto_hash *s, void *out, const size_t len)
{
	unsigned int i;

	if(!s->o) sha1_finish(s);

	/* big endian */
	for(i = 0; i < len; s->i++, i++)
		U8(out)[i] = s->h[s->i >> 2] >> (24 - ((s->i & 3) << 3));
}

static kripto_hash *sha1_create
(
	const size_t len,
	const unsigned int r
)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_sha1;

	(void)sha1_recreate(s, len, r);

	return s;
}

static void sha1_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int sha1_hash
(
	const unsigned int r,
	const void *in,
	const size_t in_len,
	void *out,
	const size_t out_len
)
{
	kripto_hash s;

	(void)sha1_recreate(&s, out_len, r);
	sha1_input(&s, in, in_len);
	sha1_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const struct kripto_hash_desc sha1 =
{
	&sha1_create,
	&sha1_recreate,
	&sha1_input,
	&sha1_output,
	&sha1_destroy,
	&sha1_hash,
	20, /* max output */
	64 /* block_size */
};

kripto_hash_desc *const kripto_hash_sha1 = &sha1;