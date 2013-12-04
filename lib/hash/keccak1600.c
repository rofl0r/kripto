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
#include <string.h>
#include <limits.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/hash.h>
#include <kripto/desc/hash.h>
#include <kripto/object/hash.h>

#include <kripto/hash/keccak1600.h>

struct kripto_hash
{
	struct kripto_hash_object obj;
	unsigned int r;
	unsigned int rate;
	unsigned int i;
	int o;
	uint8_t s[200];
};

static const uint64_t rc[48] = 
{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
	0x8000000080008082, 0x800000008000800A,
	0x8000000000000003, 0x8000000080000009,
	0x8000000000008082, 0x0000000000008009,
	0x8000000000000080, 0x0000000000008083,
	0x8000000000000081, 0x0000000000000001,
	0x000000000000800B, 0x8000000080008001,
	0x0000000000000080, 0x8000000000008000,
	0x8000000080008001, 0x0000000000000009,
	0x800000008000808B, 0x0000000000000081,
	0x8000000000000082, 0x000000008000008B,
	0x8000000080008009, 0x8000000080000000,
	0x0000000080000080, 0x0000000080008003
};

static void keccak1600_F(kripto_hash *s)
{
	uint64_t a0 = LOAD64L(s->s);
	uint64_t a1 = LOAD64L(s->s + 8);
	uint64_t a2 = LOAD64L(s->s + 16);
	uint64_t a3 = LOAD64L(s->s + 24);
	uint64_t a4 = LOAD64L(s->s + 32);
	uint64_t a5 = LOAD64L(s->s + 40);
	uint64_t a6 = LOAD64L(s->s + 48);
	uint64_t a7 = LOAD64L(s->s + 56);
	uint64_t a8 = LOAD64L(s->s + 64);
	uint64_t a9 = LOAD64L(s->s + 72);
	uint64_t a10 = LOAD64L(s->s + 80);
	uint64_t a11 = LOAD64L(s->s + 88);
	uint64_t a12 = LOAD64L(s->s + 96);
	uint64_t a13 = LOAD64L(s->s + 104);
	uint64_t a14 = LOAD64L(s->s + 112);
	uint64_t a15 = LOAD64L(s->s + 120);
	uint64_t a16 = LOAD64L(s->s + 128);
	uint64_t a17 = LOAD64L(s->s + 136);
	uint64_t a18 = LOAD64L(s->s + 144);
	uint64_t a19 = LOAD64L(s->s + 152);
	uint64_t a20 = LOAD64L(s->s + 160);
	uint64_t a21 = LOAD64L(s->s + 168);
	uint64_t a22 = LOAD64L(s->s + 176);
	uint64_t a23 = LOAD64L(s->s + 184);
	uint64_t a24 = LOAD64L(s->s + 192);

	uint64_t b0;
	uint64_t b1;
	uint64_t b2;
	uint64_t b3;
	uint64_t b4;
	uint64_t b5;
	uint64_t b6;
	uint64_t b7;
	uint64_t b8;
	uint64_t b9;
	uint64_t b10;
	uint64_t b11;
	uint64_t b12;
	uint64_t b13;
	uint64_t b14;
	uint64_t b15;
	uint64_t b16;
	uint64_t b17;
	uint64_t b18;
	uint64_t b19;
	uint64_t b20;
	uint64_t b21;
	uint64_t b22;
	uint64_t b23;
	uint64_t b24;

	uint64_t c0;
	uint64_t c1;
	uint64_t c2;
	uint64_t c3;
	uint64_t c4;

	uint64_t d0;
	uint64_t d1;
	uint64_t d2;
	uint64_t d3;
	uint64_t d4;

	unsigned int i;

	for(i = 0; i < s->r; i++)
	{
		c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
		c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
		c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
		c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
		c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;

		d0 = ROL64(c1, 1) ^ c4;
		d1 = ROL64(c2, 1) ^ c0;
		d2 = ROL64(c3, 1) ^ c1;
		d3 = ROL64(c4, 1) ^ c2;
		d4 = ROL64(c0, 1) ^ c3;

		a0 ^= d0;
		c0 = a0;
		a6 ^= d1;
		c1 = ROL64(a6, 44);
		a12 ^= d2;
		c2 = ROL64(a12, 43);
		a18 ^= d3;
		c3 = ROL64(a18, 21);
		a24 ^= d4;
		c4 = ROL64(a24, 14);

		b0 = c0 ^ ((~c1) & c2) ^ rc[i];
		b1 = c1 ^ ((~c2) & c3);
		b2 = c2 ^ ((~c3) & c4);
		b3 = c3 ^ ((~c4) & c0);
		b4 = c4 ^ ((~c0) & c1);

		a3 ^= d3;
		c0 = ROL64(a3, 28);
		a9 ^= d4;
		c1 = ROL64(a9, 20);
		a10 ^= d0;
		c2 = ROL64(a10, 3);
		a16 ^= d1;
		c3 = ROL64(a16, 45);
		a22 ^= d2;
		c4 = ROL64(a22, 61);

		b5 = c0 ^ ((~c1) & c2);
		b6 = c1 ^ ((~c2) & c3);
		b7 = c2 ^ ((~c3) & c4);
		b8 = c3 ^ ((~c4) & c0);
		b9 = c4 ^ ((~c0) & c1);

		a1 ^= d1;
		c0 = ROL64(a1, 1);
		a7 ^= d2;
		c1 = ROL64(a7, 6);
		a13 ^= d3;
		c2 = ROL64(a13, 25);
		a19 ^= d4;
		c3 = ROL64(a19, 8);
		a20 ^= d0;
		c4 = ROL64(a20, 18);

		b10 = c0 ^ ((~c1) & c2);
		b11 = c1 ^ ((~c2) & c3);
		b12 = c2 ^ ((~c3) & c4);
		b13 = c3 ^ ((~c4) & c0);
		b14 = c4 ^ ((~c0) & c1);

		a4 ^= d4;
		c0 = ROL64(a4, 27);
		a5 ^= d0;
		c1 = ROL64(a5, 36);
		a11 ^= d1;
		c2 = ROL64(a11, 10);
		a17 ^= d2;
		c3 = ROL64(a17, 15);
		a23 ^= d3;
		c4 = ROL64(a23, 56);

		b15 = c0 ^ ((~c1) & c2);
		b16 = c1 ^ ((~c2) & c3);
		b17 = c2 ^ ((~c3) & c4);
		b18 = c3 ^ ((~c4) & c0);
		b19 = c4 ^ ((~c0) & c1);

		a2 ^= d2;
		c0 = ROL64(a2, 62);
		a8 ^= d3;
		c1 = ROL64(a8, 55);
		a14 ^= d4;
		c2 = ROL64(a14, 39);
		a15 ^= d0;
		c3 = ROL64(a15, 41);
		a21 ^= d1;
		c4 = ROL64(a21, 2);

		b20 = c0 ^ ((~c1) & c2);
		b21 = c1 ^ ((~c2) & c3);
		b22 = c2 ^ ((~c3) & c4);
		b23 = c3 ^ ((~c4) & c0);
		b24 = c4 ^ ((~c0) & c1);

		a0 = b0;
		a1 = b1;
		a2 = b2;
		a3 = b3;
		a4 = b4;
		a5 = b5;
		a6 = b6;
		a7 = b7;
		a8 = b8;
		a9 = b9;
		a10 = b10;
		a11 = b11;
		a12 = b12;
		a13 = b13;
		a14 = b14;
		a15 = b15;
		a16 = b16;
		a17 = b17;
		a18 = b18;
		a19 = b19;
		a20 = b20;
		a21 = b21;
		a22 = b22;
		a23 = b23;
		a24 = b24;
	}

	STORE64L(a0, s->s);
	STORE64L(a1, s->s + 8);
	STORE64L(a2, s->s + 16);
	STORE64L(a3, s->s + 24);
	STORE64L(a4, s->s + 32);
	STORE64L(a5, s->s + 40);
	STORE64L(a6, s->s + 48);
	STORE64L(a7, s->s + 56);
	STORE64L(a8, s->s + 64);
	STORE64L(a9, s->s + 72);
	STORE64L(a10, s->s + 80);
	STORE64L(a11, s->s + 88);
	STORE64L(a12, s->s + 96);
	STORE64L(a13, s->s + 104);
	STORE64L(a14, s->s + 112);
	STORE64L(a15, s->s + 120);
	STORE64L(a16, s->s + 128);
	STORE64L(a17, s->s + 136);
	STORE64L(a18, s->s + 144);
	STORE64L(a19, s->s + 152);
	STORE64L(a20, s->s + 160);
	STORE64L(a21, s->s + 168);
	STORE64L(a22, s->s + 176);
	STORE64L(a23, s->s + 184);
	STORE64L(a24, s->s + 192);
}

static kripto_hash *keccak1600_recreate
(
	kripto_hash *s,
	unsigned int r,
	size_t len
)
{
	s->o = s->i = 0;

	s->r = r;
	if(!s->r) s->r = 24;

	s->rate = 200 - (len << 1);

	memset(s->s, 0, 200);

	return s;
}

static void keccak1600_input
(
	kripto_hash *s,
	const void *in,
	size_t len
) 
{
	size_t i;

	/* switch back to input mode */
	if(s->o) s->o = s->i = 0;

	/* input */
	for(i = 0; i < len; i++)
	{
		if(s->i == s->rate)
		{
			keccak1600_F(s);
			s->i = 0;
		}

		s->s[s->i++] ^= CU8(in)[i];
	}
}

static void keccak1600_output
(
	kripto_hash *s,
	void *out,
	size_t len
)
{
	size_t i;

	/* switch to output mode */
	if(!s->o)
	{
		/* pad */
		s->s[s->i] ^= 0x01;
		s->s[s->rate - 1] ^= 0x80;

		keccak1600_F(s);

		s->i = 0;
		s->o = -1;
	}

	/* output */
	for(i = 0; i < len; i++)
	{
		if(s->i == s->rate)
		{
			keccak1600_F(s);
			s->i = 0;
		}

		U8(out)[i] = s->s[s->i++];
	}
}

static kripto_hash *keccak1600_create(unsigned int r, size_t len)
{
	kripto_hash *s;

	s = malloc(sizeof(struct kripto_hash));
	if(!s) return 0;

	s->obj.desc = kripto_hash_keccak1600;

	(void)keccak1600_recreate(s, r, len);

	return s;
}

static void keccak1600_destroy(kripto_hash *s) 
{
	kripto_memwipe(s, sizeof(kripto_hash));
	free(s);
}

static int keccak1600_hash
(
	unsigned int r,
	const void *in,
	size_t in_len,
	void *out,
	size_t out_len
)
{
	kripto_hash s;

	(void)keccak1600_recreate(&s, r, out_len);
	keccak1600_input(&s, in, in_len);
	keccak1600_output(&s, out, out_len);

	kripto_memwipe(&s, sizeof(kripto_hash));

	return 0;
}

static const kripto_hash_desc keccak1600 =
{
	&keccak1600_create,
	&keccak1600_recreate,
	&keccak1600_input,
	&keccak1600_output,
	&keccak1600_destroy,
	&keccak1600_hash,
	SIZE_MAX, /* max output */
	200 /* block_size */
};

const kripto_hash_desc *const kripto_hash_keccak1600 = &keccak1600;
