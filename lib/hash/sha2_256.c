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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/hash_desc.h>

#include <kripto/hash/sha2_256.h>

struct kripto_hash
{
	kripto_hash_desc hash;
	unsigned int r;
	uint32_t h[8];
	uint8_t buf[64];
	unsigned int n;
	uint64_t len;
};

#define CH(X0, X1, X2) (X2 ^ (X0 & (X1 ^ X2)))
#define MAJ(X0, X1, X2) ((X0 & X1) | (X2 & (X0 | X1)))

#define S0(X) (ROR32(X, 7) ^ ROR32(X, 18) ^ ((X) >> 3))
#define S1(X) (ROR32(X, 17) ^ ROR32(X, 19) ^ ((X) >> 10))

#define E0(X) (ROR32(X, 2) ^ ROR32(X, 13) ^ ROR32(X, 22))
#define E1(X) (ROR32(X, 6) ^ ROR32(X, 11) ^ ROR32(X, 25))

static const uint32_t k[128] =
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
	0xCA273ECE, 0xD186B8C7, 0xEADA7DD6, 0xF57D4F7F,
	0x06F067AA, 0x0A637DC5, 0x113F9804, 0x1B710B35,
	0x28DB77F5, 0x32CAAB7B, 0x3C9EBE0A, 0x431D67C4,
	0x4CC5D4BE, 0x597F299C, 0x5FCB6FAB, 0x6C44198C,
	0x7BA0EA2D, 0x7EABF2D0, 0x8DBE8D03, 0x90BB1721,
	0x99A2AD45, 0x9F86E289, 0xA84C4472, 0xB3DF34FC,
	0xB99BB8D7, 0xBC76CBAB, 0xC226A69A, 0xD304F19A,
	0xDE1BE20A, 0xE39BB437, 0xEE84927C, 0xF3EDD277,
	0xFBFDFE53, 0x0BEE2C7A, 0x0E90181C, 0x25F57204,
	0x2DA45582, 0x3A52C34C, 0x41DC0172, 0x495796FC,
	0x4BD31FC6, 0x533CDE21, 0x5F7ABFE3, 0x66C206B3,
	0x6DFCC6BC, 0x7062F20F, 0x778D5127, 0x7EABA3CC,
	0x8363ECCC, 0x85BE1C25, 0x93C04028, 0x9F4A205F,
	0xA1953565, 0xA627BB0F, 0xACFA8089, 0xB3C29B23,
	0xB602F6FA, 0xC36CEE0A, 0xC7DC81EE, 0xCE7B8471,
	0xD740288C, 0xE21DBA7A, 0xEABBFF66, 0xF56A9E60
};

static void sha2_256_init(kripto_hash s, const size_t len)
{
	s->len = s->n = 0;

	if(len > 28)
	{
		/* 256 */
		s->h[0] = 0x6A09E667;
		s->h[1] = 0xBB67AE85;
		s->h[2] = 0x3C6EF372;
		s->h[3] = 0xA54FF53A;
		s->h[4] = 0x510E527F;
		s->h[5] = 0x9B05688C;
		s->h[6] = 0x1F83D9AB;
		s->h[7] = 0x5BE0CD19;
	}
	else
	{
		/* 224 */
		s->h[0] = 0xC1059ED8;
		s->h[1] = 0x367CD507;
		s->h[2] = 0x3070DD17;
		s->h[3] = 0xF70E5939;
		s->h[4] = 0xFFC00B31;
		s->h[5] = 0x68581511;
		s->h[6] = 0x64F98FA7;
		s->h[7] = 0xBEFA4FA4;
	}
}

static void sha2_256_process(kripto_hash s, const uint8_t *data)
{
	uint32_t a = s->h[0];
	uint32_t b = s->h[1];
	uint32_t c = s->h[2];
	uint32_t d = s->h[3];
	uint32_t e = s->h[4];
	uint32_t f = s->h[5];
	uint32_t g = s->h[6];
	uint32_t h = s->h[7];
	uint32_t t;
	uint32_t w[128];
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

	for(i = 16; i < s->r; i++)
		w[i] = w[i - 16] + S0(w[i - 15]) +  w[i - 7] + S1(w[i - 2]);

	for(i = 0; i < s->r; i++)
	{
		h += E1(e) + CH(e, f, g) + k[i] + w[i];
		d += h;
		h += E0(a) + MAJ(a, b, c);

		t = h;
		h = g;
		g = f;
		f = e;
		e = d;
		d = c;
		c = b;
		b = a;
		a = t;
	}

	kripto_memwipe(w, s->r << 2);

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

static int sha2_256_input(kripto_hash s, const void *in, const size_t len) 
{
	size_t i;

	s->len += len << 3;
	if(s->len < len << 3) return -1;

	for(i = 0; i < len; i++)
	{
		s->buf[s->n++] = CU8(in)[i];

		if(s->n == 64)
		{
			sha2_256_process(s, s->buf);
			s->n = 0;
		}
	}

	return 0;
}

static void sha2_256_finish(kripto_hash s)
{
	s->buf[s->n++] = 0x80; /* pad */

	if(s->n > 56) /* not enough space for length */
	{
		while(s->n < 64) s->buf[s->n++] = 0;
		sha2_256_process(s, s->buf);
		s->n = 0;
	}
	while(s->n < 56) s->buf[s->n++] = 0;

	/* add length */
	//s->len << 3;
	U64TO8_BE(s->len, s->buf + 56);

	sha2_256_process(s, s->buf);
}

static int sha2_256_output(kripto_hash s, void *out, const size_t len)
{
	unsigned int i;

	if(len > 32) return -1;

	for(i = len; i != UINT_MAX; i--)
	{
		U8(out)[i] = s->h[i >> 2];
		s->h[i >> 2] >>= 8;
	}

	return 0;
}

static kripto_hash sha2_256_create(const unsigned int r, const size_t len)
{
	kripto_hash s;

	if(r > 128) return 0;

	s = malloc(sizeof(struct kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_sha2_256;

	s->r = r;
	if(!s->r) s->r = 64;

	sha2_256_init(s, len);

	return s;
}

static void sha2_256_destroy(kripto_hash s)
{
	kripto_memwipe(s, sizeof(struct kripto_hash));
	free(s);
}

static int sha2_256_hash
(
	const unsigned int r,
	const void *in,
	const size_t in_len,
	void *out,
	const size_t out_len
)
{
	struct kripto_hash s;

	if(r > 128) return -1;

	s.r = r;
	if(!s.r) s.r = 64;

	sha2_256_init(&s, out_len);
	if(sha2_256_input(&s, in, in_len)) goto err;
	sha2_256_finish(&s);
	if(sha2_256_output(&s, out, out_len)) goto err;

	kripto_memwipe(&s, sizeof(struct kripto_hash));

	return 0;

err:
	kripto_memwipe(&s, sizeof(struct kripto_hash));
	return -1;
}

static const struct kripto_hash_desc sha2_256 =
{
	&sha2_256_init,
	&sha2_256_input,
	&sha2_256_finish,
	&sha2_256_output,
	&sha2_256_create,
	&sha2_256_destroy,
	&sha2_256_hash,
	32, /* max hash size */
	64, /* block_size */
	128, /* max_rounds */
	64 /* default_rounds */
};

kripto_hash_desc const kripto_hash_sha2_256 = &sha2_256;
