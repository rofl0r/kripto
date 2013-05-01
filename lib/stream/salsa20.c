/*
 * Copyright (C) 2011-2013 Gregor Pintar <grpintar@gmail.com>
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

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/stream_desc.h>

#include <kripto/stream/salsa20.h>

struct kripto_stream
{
	kripto_stream_desc *desc;
	unsigned int r;
	uint32_t x[16];
	uint8_t buf[64];
	unsigned int used;
};

#define QR(A, B, C, D)		\
{							\
	B ^= ROL32(A + D,  7);	\
	C ^= ROL32(B + A,  9);	\
	D ^= ROL32(C + B, 13);	\
	A ^= ROL32(D + C, 18);	\
}

static void salsa20_core
(
	const unsigned int r,
	const uint32_t *x,
	void *out
)
{
	unsigned int i;

	uint32_t x0 = x[0];
	uint32_t x1 = x[1];
	uint32_t x2 = x[2];
	uint32_t x3 = x[3];
	uint32_t x4 = x[4];
	uint32_t x5 = x[5];
	uint32_t x6 = x[6];
	uint32_t x7 = x[7];
	uint32_t x8 = x[8];
	uint32_t x9 = x[9];
	uint32_t x10 = x[10];
	uint32_t x11 = x[11];
	uint32_t x12 = x[12];
	uint32_t x13 = x[13];
	uint32_t x14 = x[14];
	uint32_t x15 = x[15];

	for(i = 0; i < r; i++)
	{
		QR(x0, x4, x8, x12);
		QR(x5, x9, x13, x1);
		QR(x10, x14, x2, x6);
		QR(x15, x3, x7, x11);

		if(++i == r) break;

		QR(x0, x1, x2, x3);
		QR(x5, x6, x7, x4);
		QR(x10, x11, x8, x9);
		QR(x15, x12, x13, x14);
	}

	x0 += x[0];
	x1 += x[1];
	x2 += x[2];
	x3 += x[3];
	x4 += x[4];
	x5 += x[5];
	x6 += x[6];
	x7 += x[7];
	x8 += x[8];
	x9 += x[9];
	x10 += x[10];
	x11 += x[11];
	x12 += x[12];
	x13 += x[13];
	x14 += x[14];
	x15 += x[15];

	U32TO8_LE(x0, U8(out));
	U32TO8_LE(x1, U8(out) + 4);
	U32TO8_LE(x2, U8(out) + 8);
	U32TO8_LE(x3, U8(out) + 12);
	U32TO8_LE(x4, U8(out) + 16);
	U32TO8_LE(x5, U8(out) + 20);
	U32TO8_LE(x6, U8(out) + 24);
	U32TO8_LE(x7, U8(out) + 28);
	U32TO8_LE(x8, U8(out) + 32);
	U32TO8_LE(x9, U8(out) + 36);
	U32TO8_LE(x10, U8(out) + 40);
	U32TO8_LE(x11, U8(out) + 44);
	U32TO8_LE(x12, U8(out) + 48);
	U32TO8_LE(x13, U8(out) + 52);
	U32TO8_LE(x14, U8(out) + 56);
	U32TO8_LE(x15, U8(out) + 60);
}

static size_t salsa20_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	const size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			salsa20_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[8])
				if(!++s->x[9]) return i;
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}

	return i;
}

static size_t salsa20_prng
(
	kripto_stream *s,
	void *out,
	const size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			salsa20_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[8])
				if(!++s->x[9]) return i;
		}

		U8(out)[i] = s->buf[s->used++];
	}

	return i;
}

static void salsa20_setup
(
	kripto_stream *s,
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r
)
{
	unsigned int i;
	unsigned int j = 0;
	unsigned int n = 0;
	uint8_t constant[16] = "expand 00-byte k";

	constant[7] += key_len / 10;
	constant[8] += key_len % 10;

	s->x[0] = U8TO32_LE(constant);

	for(i = 1; i < 5; i++)
	{
		s->x[i] = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;
	}

	s->x[5] = U8TO32_LE(constant + 4);

	/* IV */
	s->x[6] = s->x[7] = s->x[8] = s->x[9] = 0;
	for(i = 24; i < 40 && n < iv_len; i++, n++)
			s->x[i >> 2] = (s->x[i >> 2] >> 8) | (CU8(iv)[n] << 24);

	s->x[10] = U8TO32_LE(constant + 8);

	for(i = 11; i < 15; i++)
	{
		s->x[i] = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;

		s->x[i] = (s->x[i] >> 8) | (CU8(key)[j++] << 24);
		if(j == key_len) j = 0;
	}

	s->x[15] = U8TO32_LE(constant + 12);

	s->r = r;
	if(!s->r) s->r = 20;

	if(iv_len > 8) /* XSalsa20 */
	{
		for(i = 0; i < s->r; i++)
		{
			QR(s->x[0], s->x[4], s->x[8], s->x[12]);
			QR(s->x[5], s->x[9], s->x[13], s->x[1]);
			QR(s->x[10], s->x[14], s->x[2], s->x[6]);
			QR(s->x[15], s->x[3], s->x[7], s->x[11]);

			if(++i == s->r) break;

			QR(s->x[0], s->x[1], s->x[2], s->x[3]);
			QR(s->x[5], s->x[6], s->x[7], s->x[4]);
			QR(s->x[10], s->x[11], s->x[8], s->x[9]);
			QR(s->x[15], s->x[12], s->x[13], s->x[14]);
		}

		s->x[1] = s->x[0]; s->x[0] = U8TO32_LE(constant);
		s->x[2] = s->x[5]; s->x[5] = U8TO32_LE(constant + 4);
		s->x[3] = s->x[10]; s->x[10] = U8TO32_LE(constant + 8);
		s->x[4] = s->x[15]; s->x[15] = U8TO32_LE(constant + 12);

		s->x[11] = s->x[6]; s->x[6] = 0;
		s->x[12] = s->x[7]; s->x[7] = 0;

		for(i = 24; i < 32 && n < iv_len; i++, n++)
			s->x[i >> 2] = (s->x[i >> 2] >> 8) | (CU8(iv)[n] << 24);

		s->x[13] = s->x[8]; s->x[8] = 0;
		s->x[14] = s->x[9]; s->x[9] = 0;
	}

	s->used = 64;
}

static kripto_stream *salsa20_create
(
	const void *key,
	const unsigned int key_len,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int r
)
{
	kripto_stream *s;

	if(key_len > 32) return 0;
	if(iv_len > 24) return 0;

	s = malloc(sizeof(struct kripto_stream));
	if(!s) return 0;

	s->desc = kripto_stream_salsa20;

	salsa20_setup(s, key, key_len, iv, iv_len, r);

	return s;
}

static void salsa20_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(struct kripto_stream));
	free(s);
}

static const struct kripto_stream_desc salsa20 =
{
	&salsa20_crypt,
	&salsa20_crypt,
	&salsa20_prng,
	&salsa20_create,
	&salsa20_destroy,
	32,
	24,
	UINT_MAX,
	20
};

kripto_stream_desc *const kripto_stream_salsa20 = &salsa20;
