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

#include <kripto/hash/blake512.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
	unsigned int r;
	uint64_t h[8];
	/* uint64_t s[4]; */
	uint64_t len[2];
	uint8_t buf[128];
	unsigned int n;
	unsigned int out;
};

static const uint8_t sigma[10][16] =
{
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
	{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
	{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
	{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
	{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0}
};

static const uint64_t k[16] =
{
	0x243F6A8885A308D3, 0x13198A2E03707344, 
	0xA4093822299F31D0, 0x082EFA98EC4E6C89,
	0x452821E638D01377, 0xBE5466CF34E90C6C, 
	0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
	0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 
	0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
	0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 
	0x0801F2E2858EFC16, 0x636920D871574E69
};

static void blake512_init(kripto_hash *s, const size_t len)
{
	s->len[0] = s->len[1] = s->n = 0;
	s->out = len;

	if(len > 48)
	{
		/* 512 */
		s->h[0] = 0x6A09E667F3BCC908;
		s->h[1] = 0xBB67AE8584CAA73B;
		s->h[2] = 0x3C6EF372FE94F82B;
		s->h[3] = 0xA54FF53A5F1D36F1;
		s->h[4] = 0x510E527FADE682D1;
		s->h[5] = 0x9B05688C2B3E6C1F;
		s->h[6] = 0x1F83D9ABFB41BD6B;
		s->h[7] = 0x5BE0CD19137E2179;
	}
	else
	{
		/* 384 */
		s->h[0] = 0xCBBB9D5DC1059ED8;
		s->h[1] = 0x629A292A367CD507;
		s->h[2] = 0x9159015A3070DD17;
		s->h[3] = 0x152FECD8F70E5939;
		s->h[4] = 0x67332667FFC00B31;
		s->h[5] = 0x8EB44A8768581511;
		s->h[6] = 0xDB0C2E0D64F98FA7;
		s->h[7] = 0x47B5481DBEFA4FA4;
	}
}

#define G(A, B, C, D, M, S0, S1)				\
{												\
	A += B + ((M)[(S0)] ^ k[(S1)]);				\
	D = ROR64(D ^ A, 32);						\
	C += D;										\
	B = ROR64(B ^ C, 25);						\
												\
	A += B + ((M)[(S1)] ^ k[(S0)]);				\
	D = ROR64(D ^ A, 16);						\
	C += D;										\
	B = ROR64(B ^ C, 11);						\
}

static void blake512_process(kripto_hash *s, const uint8_t *data)
{
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;
	uint64_t x5;
	uint64_t x6;
	uint64_t x7;
	uint64_t x8;
	uint64_t x9;
	uint64_t x10;
	uint64_t x11;
	uint64_t x12;
	uint64_t x13;
	uint64_t x14;
	uint64_t x15;
	uint64_t m[16];
	unsigned int r;
	unsigned int i;

	m[0] = U8TO64_BE(data);
	m[1] = U8TO64_BE(data + 8);
	m[2] = U8TO64_BE(data + 16);
	m[3] = U8TO64_BE(data + 24);
	m[4] = U8TO64_BE(data + 32);
	m[5] = U8TO64_BE(data + 40);
	m[6] = U8TO64_BE(data + 48);
	m[7] = U8TO64_BE(data + 56);
	m[8] = U8TO64_BE(data + 64);
	m[9] = U8TO64_BE(data + 72);
	m[10] = U8TO64_BE(data + 80);
	m[11] = U8TO64_BE(data + 88);
	m[12] = U8TO64_BE(data + 96);
	m[13] = U8TO64_BE(data + 104);
	m[14] = U8TO64_BE(data + 112);
	m[15] = U8TO64_BE(data + 120);

	x0 = s->h[0];
	x1 = s->h[1];
	x2 = s->h[2];
	x3 = s->h[3];
	x4 = s->h[4];
	x5 = s->h[5];
	x6 = s->h[6];
	x7 = s->h[7];
	x8 = k[0]; /* ^ s->s[0] */
	x9 = k[1]; /* ^ s->s[1] */
	x10 = k[2]; /* ^ s->s[2] */
	x11 = k[3]; /* ^ s->s[3] */
	x12 = k[4] ^ s->len[0];
	x13 = k[5] ^ s->len[0];
	x14 = k[6] ^ s->len[1];
	x15 = k[7] ^ s->len[1];

	for(r = 0, i = 0; r < s->r; r++, i++)
	{
		if(i == 10) i = 0;

		G(x0, x4, x8, x12, m, sigma[i][0], sigma[i][1]);
		G(x1, x5, x9, x13, m, sigma[i][2], sigma[i][3]);
		G(x2, x6, x10, x14, m, sigma[i][4], sigma[i][5]);
		G(x3, x7, x11, x15, m, sigma[i][6], sigma[i][7]);

		G(x0, x5, x10, x15, m, sigma[i][8], sigma[i][9]);
		G(x1, x6, x11, x12, m, sigma[i][10], sigma[i][11]);
		G(x2, x7, x8, x13, m, sigma[i][12], sigma[i][13]);
		G(x3, x4, x9, x14, m, sigma[i][14], sigma[i][15]);
	}

	kripto_memwipe(m, 128);

	s->h[0] ^= x0 ^ x8; /* ^ s->s[0] */
	s->h[1] ^= x1 ^ x9; /* ^ s->s[1] */
	s->h[2] ^= x2 ^ x10; /* ^ s->s[2] */
	s->h[3] ^= x3 ^ x11; /* ^ s->s[3] */
	s->h[4] ^= x4 ^ x12; /* ^ s->s[0] */
	s->h[5] ^= x5 ^ x13; /* ^ s->s[1] */
	s->h[6] ^= x6 ^ x14; /* ^ s->s[2] */
	s->h[7] ^= x7 ^ x15; /* ^ s->s[3] */
}

static int blake512_input
(
	kripto_hash *s,
	const void *in,
	const size_t len
) 
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		s->buf[s->n++] = CU8(in)[i];

		if(s->n == 128)
		{
			s->len[0] += 1024;
			if(!s->len[0])
			{
				s->len[1]++;
				if(!s->len[1]) return -1;
			}

			blake512_process(s, s->buf);
			s->n = 0;
		}
	}

	return 0;
}

static void blake512_finish(kripto_hash *s)
{
	s->len[0] += s->n << 3;
	if(s->len[0] < (s->n << 3)) s->len[1]++;

	/* pad */
	s->buf[s->n++] = 0x80;

	if(s->n > 112) /* not enough space for length */
	{
		while(s->n < 128) s->buf[s->n++] = 0;
		blake512_process(s, s->buf);
		s->n = 0;
	}

	while(s->n < 112) s->buf[s->n++] = 0;
	if(s->out > 48) s->buf[111] ^= 0x01; /* 512 */

	/* add length */
	U64TO8_BE(s->len[1], s->buf + 112);
	U64TO8_BE(s->len[0], s->buf + 120);

	if(!s->n) s->len[0] = s->len[1] = 0;

	blake512_process(s, s->buf);
}

static int blake512_output(kripto_hash *s, void *out, const size_t len)
{
	unsigned int i;

	if(len > 64) return -1;

	for(i = len; i != UINT_MAX; i--)
	{
		U8(out)[i] = s->h[i >> 3];
		s->h[i >> 3] >>= 8;
	}

	return 0;
}

static kripto_hash *blake512_create(const unsigned int r, const size_t len)
{
	kripto_hash *s;

	if(len > 64) return 0;

	s = malloc(sizeof(struct kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_blake512;

	s->r = r;
	if(!s->r) s->r = 16;

	blake512_init(s, len);

	return s;
}

static void blake512_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(struct kripto_hash));
	free(s);
}

static int blake512_hash
(
	const unsigned int r,
	const void *in,
	const size_t in_len,
	void *out,
	const size_t out_len
)
{
	struct kripto_hash s;

	if(out_len > 64) return -1;

	s.r = r;
	if(!s.r) s.r = 16;

	blake512_init(&s, out_len);
	if(blake512_input(&s, in, in_len)) goto err;
	blake512_finish(&s);
	if(blake512_output(&s, out, out_len)) goto err;

	kripto_memwipe(&s, sizeof(struct kripto_hash));

	return 0;

err:
	kripto_memwipe(&s, sizeof(struct kripto_hash));
	return -1;
}

static const struct kripto_hash_desc blake512 =
{
	&blake512_init,
	&blake512_input,
	&blake512_finish,
	&blake512_output,
	&blake512_create,
	&blake512_destroy,
	&blake512_hash,
	64, /* max hash size */
	128, /* block_size */
	UINT_MAX, /* max_rounds */
	16 /* default_rounds */
};

kripto_hash_desc *const kripto_hash_blake512 = &blake512;
