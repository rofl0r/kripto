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
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>
#include <kripto/object/hash.h>

#include <kripto/hash/blake2s.h>

struct kripto_hash
{
	struct kripto_hash_object obj;
	unsigned int r;
	uint32_t h[8];
	uint32_t len[2];
	uint32_t f;
	uint8_t buf[64];
	unsigned int i;
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

static const uint32_t iv[8] =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static kripto_hash *blake2s_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	s->r = r;
	if(!s->r) s->r = 10;

	s->f = s->len[0] = s->len[1] = s->i = 0;

	/* s->h[0] = iv[0] ^ 0x01010020; */
	s->h[0] = iv[0] ^ 0x01010000 ^ (uint8_t)len;
	s->h[1] = iv[1];
	s->h[2] = iv[2];
	s->h[3] = iv[3];
	s->h[4] = iv[4];
	s->h[5] = iv[5];
	s->h[6] = iv[6];
	s->h[7] = iv[7];

	return s;
}

#define G(A, B, C, D, M0, M1)	\
{								\
	A += B + (M0);				\
	D = ROR32_16(D ^ A);		\
	C += D;						\
	B = ROR32_12(B ^ C);		\
								\
	A += B + (M1);				\
	D = ROR32_08(D ^ A);		\
	C += D;						\
	B = ROR32_07(B ^ C);		\
}

static void blake2s_process(kripto_hash *s, const uint8_t *data)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t x4;
	uint32_t x5;
	uint32_t x6;
	uint32_t x7;
	uint32_t x8;
	uint32_t x9;
	uint32_t x10;
	uint32_t x11;
	uint32_t x12;
	uint32_t x13;
	uint32_t x14;
	uint32_t x15;
	uint32_t m[16];
	unsigned int r;
	unsigned int i;

	m[0] = LOAD32L(data);
	m[1] = LOAD32L(data + 4);
	m[2] = LOAD32L(data + 8);
	m[3] = LOAD32L(data + 12);
	m[4] = LOAD32L(data + 16);
	m[5] = LOAD32L(data + 20);
	m[6] = LOAD32L(data + 24);
	m[7] = LOAD32L(data + 28);
	m[8] = LOAD32L(data + 32);
	m[9] = LOAD32L(data + 36);
	m[10] = LOAD32L(data + 40);
	m[11] = LOAD32L(data + 44);
	m[12] = LOAD32L(data + 48);
	m[13] = LOAD32L(data + 52);
	m[14] = LOAD32L(data + 56);
	m[15] = LOAD32L(data + 60);

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

	kripto_memwipe(m, 64);

	s->h[0] ^= x0 ^ x8;
	s->h[1] ^= x1 ^ x9;
	s->h[2] ^= x2 ^ x10;
	s->h[3] ^= x3 ^ x11;
	s->h[4] ^= x4 ^ x12;
	s->h[5] ^= x5 ^ x13;
	s->h[6] ^= x6 ^ x14;
	s->h[7] ^= x7 ^ x15;
}

static void blake2s_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->i == 64)
		{
			s->len[0] += 64;
			if(!s->len[0])
			{
				s->len[1]++;
				assert(s->len[1]);
			}

			blake2s_process(s, s->buf);
			s->i = 0;
		}

		s->buf[s->i++] = CU8(in)[i];
	}
}

static void blake2s_finish(kripto_hash *s)
{
	s->len[0] += s->i;
	if(s->len[0] < s->i) s->len[1]++;

	while(s->i < 64) s->buf[s->i++] = 0;

	s->f = 0xFFFFFFFF;

	blake2s_process(s, s->buf);

	s->i = 0;
}

static void blake2s_output(kripto_hash *s, void *out, size_t len)
{
	unsigned int i;

	if(!s->f) blake2s_finish(s);

	/* little endian */
	for(i = 0; i < len; s->i++, i++)
	{
		U8(out)[i] = s->h[s->i >> 2];
		s->h[s->i >> 2] >>= 8;
	}
}

static kripto_hash *blake2s_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(kripto_hash));
	if(!s) return 0;

	s->obj.desc = kripto_hash_blake2s;

	(void)blake2s_recreate(s, r, len);

	return s;
}

static void blake2s_destroy(kripto_hash *s)
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int blake2s_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)blake2s_recreate(&s, r, out_len);
	blake2s_input(&s, in, in_len);
	blake2s_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc blake2s =
{
	&blake2s_create,
	&blake2s_recreate,
	&blake2s_input,
	&blake2s_output,
	&blake2s_destroy,
	&blake2s_hash,
	32, /* max output */
	64 /* block_size */
};

const kripto_hash_desc *const kripto_hash_blake2s = &blake2s;
