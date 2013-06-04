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

#include <kripto/block/rc6.h>

struct kripto_block
{
	kripto_block_desc *desc;
	unsigned int rounds;
	size_t size;
	uint32_t *k;
};

#define RC6_K_LEN(r) (((r) + 2) << 1)

#define RC6_DEFAULT_ROUNDS 20
#define RC6_MAX_KEY 255

static int rc6_setup
(
	kripto_block *s,
	const uint8_t *key,
	const unsigned int key_len
)
{
	unsigned int i;
	unsigned int j;
	unsigned int k;
	const unsigned int ls = (key_len + 3) >> 2;
	uint32_t A;
	uint32_t B;
	#ifdef KRIPTO_VLA
	uint32_t L[ls];
	#elif KRIPTO_MALLOC
	uint32_t *L;
	#else
	uint32_t L[64];
	#endif

	#ifdef KRIPTO_MALLOC
	L = malloc(ls << 2);
	if(!L) return -1;
	#endif

	for(i = 0; i < ls; i++) L[i] = 0;
	for(j = key_len - 1; j != UINT_MAX; j--)
		L[j >> 2] = (L[j >> 2] << 8) | key[j];

	if(!s->rounds) s->rounds = RC6_DEFAULT_ROUNDS;

	*s->k = 0xB7E15163;
	for(i = 1; i < RC6_K_LEN(s->rounds); i++)
		s->k[i] = s->k[i-1] + 0x9E3779B9;

	A = B = i = j = k = 0;
	while(k < RC6_K_LEN(s->rounds) * 3)
	{
		A = s->k[i] = ROL32(s->k[i] + A + B, 3);
		B = L[j] = ROL32(L[j] + A + B, A + B);
		if(++i == RC6_K_LEN(s->rounds)) i = 0;
		if(++j == ls) j = 0;
		k++;
	}

	/* wipe */
	kripto_memwipe(L, ls << 2);
	kripto_memwipe(&A, sizeof(uint32_t));
	kripto_memwipe(&B, sizeof(uint32_t));

	#ifdef KRIPTO_MALLOC
	free(L);
	#endif

	return 0;
}

static void rc6_encrypt(const kripto_block *s, const void *pt, void *ct)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t Bm;
	uint32_t Dm;
	uint32_t t;
	unsigned int i = 2;

	A = U8TO32_LE(CU8(pt));
	B = U8TO32_LE(CU8(pt) + 4);
	C = U8TO32_LE(CU8(pt) + 8);
	D = U8TO32_LE(CU8(pt) + 12);

	B += s->k[0];
	D += s->k[1];

	while(i <= (s->rounds << 1))
	{
		Bm = ROL32(B * ((B << 1) | 1), 5);
		Dm = ROL32(D * ((D << 1) | 1), 5);

		t = ROL32(A ^ Bm, Dm & 31) + s->k[i++];
		A = B;
		B = ROL32(C ^ Dm, Bm & 31) + s->k[i++];
		C = D;
		D = t;
	}

	A += s->k[i];
	C += s->k[i + 1];

	U32TO8_LE(A, U8(ct));
	U32TO8_LE(B, U8(ct) + 4);
	U32TO8_LE(C, U8(ct) + 8);
	U32TO8_LE(D, U8(ct) + 12);
}

static void rc6_decrypt(const kripto_block *s, const void *ct, void *pt)
{
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t Am;
	uint32_t Cm;
	uint32_t t;
	unsigned int i = s->rounds << 1;

	A = U8TO32_LE(CU8(ct));
	B = U8TO32_LE(CU8(ct) + 4);
	C = U8TO32_LE(CU8(ct) + 8);
	D = U8TO32_LE(CU8(ct) + 12);

	A -= s->k[i + 2];
	C -= s->k[i + 3];

	while(i)
	{
		Am = ROL32(A * ((A << 1) | 1), 5);
		Cm = ROL32(C * ((C << 1) | 1), 5);

		t = D;
		D = C;
		C = ROR32(B - s->k[i+1], Am & 31) ^ Cm;
		B = A;
		A = ROR32(t - s->k[i], Cm & 31) ^ Am;

		i -= 2;
	}

	B -= s->k[0];
	D -= s->k[1];

	U32TO8_LE(A, U8(pt));
	U32TO8_LE(B, U8(pt) + 4);
	U32TO8_LE(C, U8(pt) + 8);
	U32TO8_LE(D, U8(pt) + 12);
}

static kripto_block *rc6_create
(
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	kripto_block *s;

	if(!r) r = RC6_DEFAULT_ROUNDS;

	s = malloc(sizeof(kripto_block) + (RC6_K_LEN(r) << 2));
	if(!s) return 0;

	s->desc = kripto_block_rc6;
	s->size = sizeof(kripto_block) + (RC6_K_LEN(r) << 2);
	s->rounds = r;
	s->k = (uint32_t *)((uint8_t *)s + sizeof(kripto_block));

	if(rc6_setup(s, key, key_len))
	{
		free(s);
		return 0;
	}

	return s;
}

static void rc6_destroy(kripto_block *s)
{
	kripto_memwipe(s, s->size);
	free(s);
}

static kripto_block *rc6_change
(
	kripto_block *s,
	const void *key,
	unsigned int key_len,
	unsigned int r
)
{
	if(!r) r = RC6_DEFAULT_ROUNDS;

	if(sizeof(kripto_block) + (RC6_K_LEN(r) << 2) > s->size)
	{
		rc6_destroy(s);
		s = rc6_create(key, key_len, r);
	}
	else
	{
		s->rounds = r;

		if(rc6_setup(s, key, key_len))
		{
			free(s);
			return 0;
		}
	}

	return s;
}

static const struct kripto_block_desc rc6 =
{
	&rc6_encrypt,
	&rc6_decrypt,
	&rc6_create,
	&rc6_change,
	&rc6_destroy,
	16, /* block size */
	255, /* max key */
	INT_MAX, /* max rounds */
	20 /* default rounds */
};

kripto_block_desc *const kripto_block_rc6 = &rc6;
