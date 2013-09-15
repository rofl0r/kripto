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

#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/desc/stream.h>

#include <kripto/stream/chacha.h>

struct kripto_stream
{
	const kripto_stream_desc *desc;
	unsigned int r;
	uint32_t x[16];
	uint8_t buf[64];
	unsigned int used;
};

#define QR(A, B, C, D)				\
{									\
	A += B; D = ROL32(D ^ A, 16);	\
	C += D; B = ROL32(B ^ C, 12);	\
	A += B; D = ROL32(D ^ A,  8);	\
	C += D; B = ROL32(B ^ C,  7);	\
}

static void chacha_core
(
	unsigned int r,
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
		QR(x1, x5, x9, x13);
		QR(x2, x6, x10, x14);
		QR(x3, x7, x11, x15);

		if(++i == r) break;

		QR(x0, x5, x10, x15);
		QR(x1, x6, x11, x12);
		QR(x2, x7, x8, x13);
		QR(x3, x4, x9, x14);
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

	STORE32L(x0, U8(out));
	STORE32L(x1, U8(out) + 4);
	STORE32L(x2, U8(out) + 8);
	STORE32L(x3, U8(out) + 12);
	STORE32L(x4, U8(out) + 16);
	STORE32L(x5, U8(out) + 20);
	STORE32L(x6, U8(out) + 24);
	STORE32L(x7, U8(out) + 28);
	STORE32L(x8, U8(out) + 32);
	STORE32L(x9, U8(out) + 36);
	STORE32L(x10, U8(out) + 40);
	STORE32L(x11, U8(out) + 44);
	STORE32L(x12, U8(out) + 48);
	STORE32L(x13, U8(out) + 52);
	STORE32L(x14, U8(out) + 56);
	STORE32L(x15, U8(out) + 60);
}

static void chacha_crypt
(
	kripto_stream *s,
	const void *in,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			chacha_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[12])
				++s->x[13];
		}

		U8(out)[i] = CU8(in)[i] ^ s->buf[s->used++];
	}
}

static void chacha_prng
(
	kripto_stream *s,
	void *out,
	size_t len
)
{
	size_t i;

	for(i = 0; i < len; i++)
	{
		if(s->used == 64)
		{
			chacha_core(s->r, s->x, s->buf);
			s->used = 0;

			if(!++s->x[12])
				++s->x[13];
		}

		U8(out)[i] = s->buf[s->used++];
	}
}

static kripto_stream *chacha_recreate
(
	kripto_stream *s,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	unsigned int i;
	unsigned int j = 0;
	uint8_t constant[16] = "expand 00-byte k";

	constant[7] += key_len / 10;
	constant[8] += key_len % 10;

	s->x[0] = LOAD32L(constant);
	s->x[1] = LOAD32L(constant + 4);
	s->x[2] = LOAD32L(constant + 8);
	s->x[3] = LOAD32L(constant + 12);

	for(i = 4; i < 12; i++)
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

	/* IV */
	s->x[12] = s->x[13] = s->x[14] = s->x[15] = 0;

	if(iv_len > 8) i = 48; /* XChaCha */
	else i = 56;

	for(; i < 64 && j < iv_len; i++, j++)
			s->x[i >> 2] = (s->x[i >> 2] >> 8) | (CU8(iv)[j] << 24);

	s->r = r;
	if(!s->r) s->r = 20;

	if(iv_len > 8) /* XChaCha */
	{
		for(i = 0; i < s->r; i++)
		{
			QR(s->x[0], s->x[4], s->x[8], s->x[12]);
			QR(s->x[1], s->x[5], s->x[9], s->x[13]);
			QR(s->x[2], s->x[6], s->x[10], s->x[14]);
			QR(s->x[3], s->x[7], s->x[11], s->x[15]);

			if(++i == s->r) break;

			QR(s->x[0], s->x[5], s->x[10], s->x[15]);
			QR(s->x[1], s->x[6], s->x[11], s->x[12]);
			QR(s->x[2], s->x[7], s->x[8], s->x[13]);
			QR(s->x[3], s->x[4], s->x[9], s->x[14]);
		}

		s->x[4] = s->x[0]; s->x[0] = LOAD32L(constant);
		s->x[5] = s->x[1]; s->x[1] = LOAD32L(constant + 4);
		s->x[6] = s->x[2]; s->x[2] = LOAD32L(constant + 8);
		s->x[7] = s->x[3]; s->x[3] = LOAD32L(constant + 12);

		s->x[8] = s->x[12]; s->x[12] = 0;
		s->x[9] = s->x[13]; s->x[13] = 0;
		s->x[10] = s->x[14]; s->x[14] = 0;
		s->x[11] = s->x[15]; s->x[15] = 0;

		for(i = 56; i < 64 && j < iv_len; i++, j++)
			s->x[i >> 2] = (s->x[i >> 2] >> 8) | (CU8(iv)[j] << 24);
	}

	s->used = 64;

	return s;
}

static kripto_stream *chacha_create
(
	const kripto_stream_desc *desc,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *iv,
	unsigned int iv_len
)
{
	kripto_stream *s;

	(void)desc;

	s = malloc(sizeof(kripto_stream));
	if(!s) return 0;

	s->desc = kripto_stream_chacha;

	(void)chacha_recreate(s, r, key, key_len, iv, iv_len);

	return s;
}

static void chacha_destroy(kripto_stream *s)
{
	kripto_memwipe(s, sizeof(kripto_stream));
	free(s);
}

static const struct kripto_stream_desc chacha =
{
	&chacha_create,
	&chacha_recreate,
	&chacha_crypt,
	&chacha_crypt,
	&chacha_prng,
	&chacha_destroy,
	1,
	32, /* max key */
	24 /* max iv */
};

const kripto_stream_desc *const kripto_stream_chacha = &chacha;
