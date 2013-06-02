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

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>

#include <kripto/block/noekeon.h>

struct kripto_block
{
	kripto_block_desc *desc;
	unsigned int r;
	uint32_t k[4];
	uint32_t dk[4];
};

#define NOEKEON_MAX_KEY 16
#define NOEKEON_MAX_ROUNDS 32
#define NOEKEON_DEFAULT_ROUNDS 16

static const uint8_t rc[34] =
{
	0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
	0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
	0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
	0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25,
	0x4A, 0x94
};

#define THETA(X0, X1, X2, X3, K0, K1, K2, K3)	\
{												\
	T = X0 ^ X2;								\
	T ^= ROL32(T, 8) ^ ROR32(T, 8);				\
	X1 ^= T;									\
	X3 ^= T;									\
	X0 ^= K0; X1 ^= K1; X2 ^= K2; X3 ^= K3;		\
	T = X1 ^ X3;								\
	T ^= ROL32(T, 8) ^ ROR32(T, 8);				\
	X0 ^= T;									\
	X2 ^= T;									\
}

#define GAMMA(X0, X1, X2, X3)	\
{								\
	X1 ^= ~(X3 | X2);			\
	X0 ^= X2 & X1;				\
	T = X3; X3 = X0; X0 = T;	\
	X2 ^= X0 ^ X1 ^ X3;			\
	X1 ^= ~(X3 | X2);			\
	X0 ^= X2 & X1;				\
}

#define PI1(X1, X2, X3)	\
{						\
	X1 = ROL32(X1, 1);	\
	X2 = ROL32(X2, 5);	\
	X3 = ROL32(X3, 2);	\
}

#define PI2(X1, X2, X3)	\
{						\
	X1 = ROR32(X1, 1);	\
	X2 = ROR32(X2, 5);	\
	X3 = ROR32(X3, 2);	\
}

static void noekeon_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t T;
	unsigned int r;

	x0 = U8TO32_BE(CU8(pt));
	x1 = U8TO32_BE(CU8(pt) + 4);
	x2 = U8TO32_BE(CU8(pt) + 8);
	x3 = U8TO32_BE(CU8(pt) + 12);

	for(r = 0; r < s->r; r++)
	{
		x0 ^= rc[r];
		THETA(x0, x1, x2, x3, s->k[0], s->k[1], s->k[2], s->k[3]);
		PI1(x1, x2, x3);
		GAMMA(x0, x1, x2, x3);
		PI2(x1, x2, x3);
	}
	x0 ^= rc[r];
	THETA(x0, x1, x2, x3, s->k[0], s->k[1], s->k[2], s->k[3]);

	U32TO8_BE(x0, U8(ct));
	U32TO8_BE(x1, U8(ct) + 4);
	U32TO8_BE(x2, U8(ct) + 8);
	U32TO8_BE(x3, U8(ct) + 12);
}

static void noekeon_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;
	uint32_t T;
	unsigned int r;

	x0 = U8TO32_BE(CU8(ct));
	x1 = U8TO32_BE(CU8(ct) + 4);
	x2 = U8TO32_BE(CU8(ct) + 8);
	x3 = U8TO32_BE(CU8(ct) + 12);

	for(r = s->r; r; r--)
	{
		THETA(x0, x1, x2, x3, s->dk[0], s->dk[1], s->dk[2], s->dk[3]);
		x0 ^= rc[r];
		PI1(x1, x2, x3);
		GAMMA(x0, x1, x2, x3);
		PI2(x1, x2, x3);
	}
	THETA(x0, x1, x2, x3, s->dk[0], s->dk[1], s->dk[2], s->dk[3]);
	x0 ^= rc[r];

	U32TO8_BE(x0, U8(pt));
	U32TO8_BE(x1, U8(pt) + 4);
	U32TO8_BE(x2, U8(pt) + 8);
	U32TO8_BE(x3, U8(pt) + 12);
}

static void noekeon_setup
(
	kripto_block *s,
	const uint8_t *key,
	const unsigned int key_len
)
{
	unsigned int i;
	uint32_t T;
	struct kripto_block ts;

	#ifndef NOEKEON_DIRECT
	uint8_t tk[16];
	#endif

	if(!s->r) s->r = NOEKEON_DEFAULT_ROUNDS;

	#ifndef NOEKEON_DIRECT

	/* indirect */

	ts.k[0] = ts.k[1] = ts.k[2] = ts.k[3] = 0;

	for(i = 0; i < key_len; i++) tk[i] = key[i];
	while(i < 16) tk[i++] = 0;

	ts.r = s->r;
	noekeon_encrypt(&ts, tk, tk);
	s->k[0] = U8TO32_BE(tk);
	s->k[1] = U8TO32_BE(tk + 4);
	s->k[2] = U8TO32_BE(tk + 8);
	s->k[3] = U8TO32_BE(tk + 12);

	/* wipe */
	kripto_memwipe(tk, 16);

	#else

	/* direct */
	s->k[0] = s->k[1] = s->k[2] = s->k[3] = 0;
	for(i = 0; i < key_len; i++)
		s->k[i >> 2] = (s->k[i >> 2] << 8) | key[i];

	#endif

	/* decryption key */
	s->dk[0] = s->k[0];
	s->dk[1] = s->k[1];
	s->dk[2] = s->k[2];
	s->dk[3] = s->k[3];
	THETA(s->dk[0], s->dk[1], s->dk[2], s->dk[3], 0, 0, 0, 0);
}

static kripto_block *noekeon_create
(
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	kripto_block *s;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->desc = kripto_block_noekeon;
	s->r = r;

	noekeon_setup(s, key, key_len);

	return s;
}

static kripto_block *noekeon_change
(
	kripto_block *s,
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	s->r = r;
	noekeon_setup(s, key, key_len);

	return s;
}

static void noekeon_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static const struct kripto_block_desc noekeon =
{
	&noekeon_encrypt,
	&noekeon_decrypt,
	&noekeon_create,
	&noekeon_change,
	&noekeon_destroy,
	16, /* block size */
	16, /* max key */
	32, /* max rounds */
	16 /* default rounds */
};

kripto_block_desc *const kripto_block_noekeon = &noekeon;
