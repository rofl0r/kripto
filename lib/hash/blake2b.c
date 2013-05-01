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

#include <kripto/hash/blake2b.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
	unsigned int r;
	uint64_t h[8];
	uint64_t len[2];
	uint64_t f;
	uint8_t buf[128];
	unsigned int n;
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

static const uint64_t iv[8] =
{
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static void blake2b_init(kripto_hash *s, const size_t len)
{
	s->f = s->len[0] = s->len[1] = s->n = 0;

	/* s->h[0] = iv[0] ^ 0x0000000001010040; */
	s->h[0] = iv[0] ^ 0x0000000001010000 ^ (uint8_t)len;
	s->h[1] = iv[1];
	s->h[2] = iv[2];
	s->h[3] = iv[3];
	s->h[4] = iv[4];
	s->h[5] = iv[5];
	s->h[6] = iv[6];
	s->h[7] = iv[7];
}

#define G(A, B, C, D, M0, M1)	\
{								\
	A += B + (M0);				\
	D = ROR64(D ^ A, 32);		\
	C += D;						\
	B = ROR64(B ^ C, 24);		\
								\
	A += B + (M1);				\
	D = ROR64(D ^ A, 16);		\
	C += D;						\
	B = ROR64(B ^ C, 63);		\
}

static void blake2b_process(kripto_hash *s, const uint8_t *data)
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

	m[0] = U8TO64_LE(data);
	m[1] = U8TO64_LE(data + 8);
	m[2] = U8TO64_LE(data + 16);
	m[3] = U8TO64_LE(data + 24);
	m[4] = U8TO64_LE(data + 32);
	m[5] = U8TO64_LE(data + 40);
	m[6] = U8TO64_LE(data + 48);
	m[7] = U8TO64_LE(data + 56);
	m[8] = U8TO64_LE(data + 64);
	m[9] = U8TO64_LE(data + 72);
	m[10] = U8TO64_LE(data + 80);
	m[11] = U8TO64_LE(data + 88);
	m[12] = U8TO64_LE(data + 96);
	m[13] = U8TO64_LE(data + 104);
	m[14] = U8TO64_LE(data + 112);
	m[15] = U8TO64_LE(data + 120);

	x0 = s->h[0];
	x1 = s->h[1];
	x2 = s->h[2];
	x3 = s->h[3];
	x4 = s->h[4];
	x5 = s->h[5];
	x6 = s->h[6];
	x7 = s->h[7];
	x8 = iv[0];
	x9 = iv[1];
	x10 = iv[2];
	x11 = iv[3];
	x12 = iv[4] ^ s->len[0];
	x13 = iv[5] ^ s->len[1];
	x14 = iv[6] ^ s->f;
	x15 = iv[7];

	for(r = 0, i = 0; r < s->r; r++, i++)
	{
		if(i == 10) i = 0;

		G(x0, x4, x8, x12, m[sigma[i][0]], m[sigma[i][1]]);
		G(x1, x5, x9, x13, m[sigma[i][2]], m[sigma[i][3]]);
		G(x2, x6, x10, x14, m[sigma[i][4]], m[sigma[i][5]]);
		G(x3, x7, x11, x15, m[sigma[i][6]], m[sigma[i][7]]);

		G(x0, x5, x10, x15, m[sigma[i][8]], m[sigma[i][9]]);
		G(x1, x6, x11, x12, m[sigma[i][10]], m[sigma[i][11]]);
		G(x2, x7, x8, x13, m[sigma[i][12]], m[sigma[i][13]]);
		G(x3, x4, x9, x14, m[sigma[i][14]], m[sigma[i][15]]);
	}

	kripto_memwipe(m, 128);

	s->h[0] ^= x0 ^ x8;
	s->h[1] ^= x1 ^ x9;
	s->h[2] ^= x2 ^ x10;
	s->h[3] ^= x3 ^ x11;
	s->h[4] ^= x4 ^ x12;
	s->h[5] ^= x5 ^ x13;
	s->h[6] ^= x6 ^ x14;
	s->h[7] ^= x7 ^ x15;
}

static int blake2b_input(kripto_hash *s, const void *in, const size_t len) 
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->n == 128)
		{
			s->len[0] += 128;
			if(!s->len[0])
				if(!++s->len[1]) return -1;

			blake2b_process(s, s->buf);
			s->n = 0;
		}

		s->buf[s->n++] = CU8(in)[i];
	}

	return 0;
}

static void blake2b_finish(kripto_hash *s)
{
	s->len[0] += s->n;
	if(s->len[0] < s->n) s->len[1]++;

	while(s->n < 128) s->buf[s->n++] = 0;

	s->f = 0xFFFFFFFFFFFFFFFF;

	blake2b_process(s, s->buf);
}

static int blake2b_output(kripto_hash *s, void *out, const size_t len)
{
	unsigned int i;

	if(len > 64) return -1;

	for(i = 0; i < len; i++)
	{
		U8(out)[i] = s->h[i >> 3];
		s->h[i >> 3] >>= 8;
	}

	return 0;
}

static kripto_hash *blake2b_create(const unsigned int r, const size_t len)
{
	kripto_hash *s;

	if(len > 64) return 0;

	s = malloc(sizeof(struct kripto_hash));
	if(!s) return 0;

	s->hash = kripto_hash_blake2b;

	s->r = r;
	if(!s->r) s->r = 12;

	blake2b_init(s, len);

	return s;
}

static void blake2b_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(struct kripto_hash));
	free(s);
}

static int blake2b_hash
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
	if(!s.r) s.r = 12;

	blake2b_init(&s, out_len);
	if(blake2b_input(&s, in, in_len)) goto err;
	blake2b_finish(&s);
	if(blake2b_output(&s, out, out_len)) goto err;

	kripto_memwipe(&s, sizeof(struct kripto_hash));

	return 0;

err:
	kripto_memwipe(&s, sizeof(struct kripto_hash));
	return -1;
}

static const struct kripto_hash_desc blake2b =
{
	&blake2b_init,
	&blake2b_input,
	&blake2b_finish,
	&blake2b_output,
	&blake2b_create,
	&blake2b_destroy,
	&blake2b_hash,
	64, /* max hash size */
	128, /* block_size */
	UINT_MAX, /* max_rounds */
	12 /* default_rounds */
};

kripto_hash_desc *const kripto_hash_blake2b = &blake2b;
