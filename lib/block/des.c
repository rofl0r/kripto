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

/* D3DES (V5.09) - 
 *
 * A portable, public domain, version of the Data Encryption Standard.
 *
 * Written with Symantec's THINK (ightspeed) C by Richard Outerbridge.
 * Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
 * code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
 * Ferguson, Eric Young and Dana How for comparing notes; and Ray au,
 * for humouring me on. 
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kripto/cast.h>
#include <kripto/loadstore.h>
#include <kripto/rotate.h>
#include <kripto/memwipe.h>
#include <kripto/block.h>
#include <kripto/desc/block.h>
#include <kripto/object/block.h>

#include <kripto/block/des.h>

struct kripto_block
{
	struct kripto_block_object obj;
	int tdes;
	uint32_t ek[3][32];
	uint32_t dk[3][32];
};

static const uint8_t bytebit[8] =
{
	0200, 0100, 0040, 0020, 0010, 0004, 0002, 0001
};

static const uint32_t bigbyte[24] =
{
	0x800000, 0x400000, 0x200000, 0x100000,
	0x080000, 0x040000, 0x020000, 0x010000,
	0x008000, 0x004000, 0x002000, 0x001000,
	0x000800, 0x000400, 0x000200, 0x000100,
	0x000080, 0x000040, 0x000020, 0x000010,
	0x000008, 0x000004, 0x000002, 0x000001
};

static const uint8_t pc1[56] =
{
	56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
};

static const uint8_t pc2[48] =
{
	13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

static const uint8_t totrot[16] =
{
	1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

static void des_key
(
	const uint8_t *key,
	unsigned int len,
	int decrypt,
	uint32_t *k
)
{
	/* Thanks to James Gillogly & Phil Karn! */

	unsigned int i;
	unsigned int j;
	uint8_t l;
	unsigned int m;
	unsigned int n;
	uint8_t pc1m[56];
	uint8_t pcr[56];
	uint32_t kn[32];

	memcpy(pcr, key, len);
	memset(pcr + len, 0, 8 - len);

	for(j = 0; j < 56; j++)
	{
		l = pc1[j];
		m = l & 7;
		pc1m[j] = (pcr[l >> 3] & bytebit[m]) ? 1 : 0;
	}

	for(i = 0; i < 16; i++)
	{
		if(decrypt) m = (15 - i) << 1;
		else m = i << 1;

		n = m + 1;
		kn[m] = kn[n] = 0;

		for(j = 0; j < 28; j++)
		{
			l = j + totrot[i];
			if(l < 28) pcr[j] = pc1m[l];
			else pcr[j] = pc1m[l - 28];
		}

		for(; j < 56; j++)
		{
			l = j + totrot[i];
			if(l < 56) pcr[j] = pc1m[l];
			else pcr[j] = pc1m[l - 28];
		}

		for(j = 0; j < 24; j++)
		{
			if(pcr[pc2[j]]) kn[m] |= bigbyte[j];
			if(pcr[pc2[j + 24]]) kn[n] |= bigbyte[j];
		}
	}

	for(i = 0; i < 32; i++)
	{
		j = i++;

		*k++ = ((kn[j] & 0x00FC0000) << 6)
			| ((kn[j] & 0x00000FC0) << 10)
			| ((kn[i] & 0x00FC0000) >> 10)
			| ((kn[i] & 0x00000FC0) >> 6);

		*k++ = ((kn[j] & 0x0003F000) << 12)
			| ((kn[j] & 0x0000003F) << 16)
			| ((kn[i] & 0x0003F000) >> 4)
			| (kn[i] & 0x0000003F);
	}

	kripto_memwipe(kn, 128);
	kripto_memwipe(pcr, 56);
	kripto_memwipe(pc1m, 56);
}

static void des_setup
(
	kripto_block *s,
	const uint8_t *key,
	unsigned int len
)
{
	if(len > 16) /* three keys */
	{
		s->tdes = -1;

		des_key(key, 8, 0, s->ek[0]);
		des_key(key + 8, 8, -1, s->ek[1]);
		des_key(key + 16, len - 16, 0, s->ek[2]);

		des_key(key, 8, -1, s->dk[2]);
		des_key(key + 8, 8, 0, s->dk[1]);
		des_key(key + 16, len - 16, -1, s->dk[0]);
	}
	else if(len > 8) /* two keys */
	{
		s->tdes = -1;

		des_key(key, 8, 0, s->ek[0]);
		des_key(key + 8, len - 8, -1, s->ek[1]);
		des_key(key, 8, 0, s->ek[2]);

		des_key(key, 8, -1, s->dk[2]);
		des_key(key + 8, len - 8, 0, s->dk[1]);
		des_key(key, 8, -1, s->dk[0]);
	}
	else /* one key */
	{
		s->tdes = 0;

		des_key(key, len, 0, *s->ek);
		des_key(key, len, -1, *s->dk);
	}
}

static const uint32_t SP1[64] =
{
	0x01010400, 0x00000000, 0x00010000, 0x01010404,
	0x01010004, 0x00010404, 0x00000004, 0x00010000,
	0x00000400, 0x01010400, 0x01010404, 0x00000400,
	0x01000404, 0x01010004, 0x01000000, 0x00000004,
	0x00000404, 0x01000400, 0x01000400, 0x00010400,
	0x00010400, 0x01010000, 0x01010000, 0x01000404,
	0x00010004, 0x01000004, 0x01000004, 0x00010004,
	0x00000000, 0x00000404, 0x00010404, 0x01000000,
	0x00010000, 0x01010404, 0x00000004, 0x01010000,
	0x01010400, 0x01000000, 0x01000000, 0x00000400,
	0x01010004, 0x00010000, 0x00010400, 0x01000004,
	0x00000400, 0x00000004, 0x01000404, 0x00010404,
	0x01010404, 0x00010004, 0x01010000, 0x01000404,
	0x01000004, 0x00000404, 0x00010404, 0x01010400,
	0x00000404, 0x01000400, 0x01000400, 0x00000000,
	0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const uint32_t SP2[64] =
{
	0x80108020, 0x80008000, 0x00008000, 0x00108020,
	0x00100000, 0x00000020, 0x80100020, 0x80008020,
	0x80000020, 0x80108020, 0x80108000, 0x80000000,
	0x80008000, 0x00100000, 0x00000020, 0x80100020,
	0x00108000, 0x00100020, 0x80008020, 0x00000000,
	0x80000000, 0x00008000, 0x00108020, 0x80100000,
	0x00100020, 0x80000020, 0x00000000, 0x00108000,
	0x00008020, 0x80108000, 0x80100000, 0x00008020,
	0x00000000, 0x00108020, 0x80100020, 0x00100000,
	0x80008020, 0x80100000, 0x80108000, 0x00008000,
	0x80100000, 0x80008000, 0x00000020, 0x80108020,
	0x00108020, 0x00000020, 0x00008000, 0x80000000,
	0x00008020, 0x80108000, 0x00100000, 0x80000020,
	0x00100020, 0x80008020, 0x80000020, 0x00100020,
	0x00108000, 0x00000000, 0x80008000, 0x00008020,
	0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const uint32_t SP3[64] =
{
	0x00000208, 0x08020200, 0x00000000, 0x08020008,
	0x08000200, 0x00000000, 0x00020208, 0x08000200,
	0x00020008, 0x08000008, 0x08000008, 0x00020000,
	0x08020208, 0x00020008, 0x08020000, 0x00000208,
	0x08000000, 0x00000008, 0x08020200, 0x00000200,
	0x00020200, 0x08020000, 0x08020008, 0x00020208,
	0x08000208, 0x00020200, 0x00020000, 0x08000208,
	0x00000008, 0x08020208, 0x00000200, 0x08000000,
	0x08020200, 0x08000000, 0x00020008, 0x00000208,
	0x00020000, 0x08020200, 0x08000200, 0x00000000,
	0x00000200, 0x00020008, 0x08020208, 0x08000200,
	0x08000008, 0x00000200, 0x00000000, 0x08020008,
	0x08000208, 0x00020000, 0x08000000, 0x08020208,
	0x00000008, 0x00020208, 0x00020200, 0x08000008,
	0x08020000, 0x08000208, 0x00000208, 0x08020000,
	0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const uint32_t SP4[64] =
{
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802080, 0x00800081, 0x00800001, 0x00002001,
	0x00000000, 0x00802000, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00800080, 0x00800001,
	0x00000001, 0x00002000, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002001, 0x00002080,
	0x00800081, 0x00000001, 0x00002080, 0x00800080,
	0x00002000, 0x00802080, 0x00802081, 0x00000081,
	0x00800080, 0x00800001, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00000000, 0x00802000,
	0x00002080, 0x00800080, 0x00800081, 0x00000001,
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802081, 0x00000081, 0x00000001, 0x00002000,
	0x00800001, 0x00002001, 0x00802080, 0x00800081,
	0x00002001, 0x00002080, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const uint32_t SP5[64] =
{
	0x00000100, 0x02080100, 0x02080000, 0x42000100,
	0x00080000, 0x00000100, 0x40000000, 0x02080000,
	0x40080100, 0x00080000, 0x02000100, 0x40080100,
	0x42000100, 0x42080000, 0x00080100, 0x40000000,
	0x02000000, 0x40080000, 0x40080000, 0x00000000,
	0x40000100, 0x42080100, 0x42080100, 0x02000100,
	0x42080000, 0x40000100, 0x00000000, 0x42000000,
	0x02080100, 0x02000000, 0x42000000, 0x00080100,
	0x00080000, 0x42000100, 0x00000100, 0x02000000,
	0x40000000, 0x02080000, 0x42000100, 0x40080100,
	0x02000100, 0x40000000, 0x42080000, 0x02080100,
	0x40080100, 0x00000100, 0x02000000, 0x42080000,
	0x42080100, 0x00080100, 0x42000000, 0x42080100,
	0x02080000, 0x00000000, 0x40080000, 0x42000000,
	0x00080100, 0x02000100, 0x40000100, 0x00080000,
	0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const uint32_t SP6[64] =
{
	0x20000010, 0x20400000, 0x00004000, 0x20404010,
	0x20400000, 0x00000010, 0x20404010, 0x00400000,
	0x20004000, 0x00404010, 0x00400000, 0x20000010,
	0x00400010, 0x20004000, 0x20000000, 0x00004010,
	0x00000000, 0x00400010, 0x20004010, 0x00004000,
	0x00404000, 0x20004010, 0x00000010, 0x20400010,
	0x20400010, 0x00000000, 0x00404010, 0x20404000,
	0x00004010, 0x00404000, 0x20404000, 0x20000000,
	0x20004000, 0x00000010, 0x20400010, 0x00404000,
	0x20404010, 0x00400000, 0x00004010, 0x20000010,
	0x00400000, 0x20004000, 0x20000000, 0x00004010,
	0x20000010, 0x20404010, 0x00404000, 0x20400000,
	0x00404010, 0x20404000, 0x00000000, 0x20400010,
	0x00000010, 0x00004000, 0x20400000, 0x00404010,
	0x00004000, 0x00400010, 0x20004010, 0x00000000,
	0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const uint32_t SP7[64] =
{
	0x00200000, 0x04200002, 0x04000802, 0x00000000,
	0x00000800, 0x04000802, 0x00200802, 0x04200800,
	0x04200802, 0x00200000, 0x00000000, 0x04000002,
	0x00000002, 0x04000000, 0x04200002, 0x00000802,
	0x04000800, 0x00200802, 0x00200002, 0x04000800,
	0x04000002, 0x04200000, 0x04200800, 0x00200002,
	0x04200000, 0x00000800, 0x00000802, 0x04200802,
	0x00200800, 0x00000002, 0x04000000, 0x00200800,
	0x04000000, 0x00200800, 0x00200000, 0x04000802,
	0x04000802, 0x04200002, 0x04200002, 0x00000002,
	0x00200002, 0x04000000, 0x04000800, 0x00200000,
	0x04200800, 0x00000802, 0x00200802, 0x04200800,
	0x00000802, 0x04000002, 0x04200802, 0x04200000,
	0x00200800, 0x00000000, 0x00000002, 0x04200802,
	0x00000000, 0x00200802, 0x04200000, 0x00000800,
	0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const uint32_t SP8[64] =
{
	0x10001040, 0x00001000, 0x00040000, 0x10041040,
	0x10000000, 0x10001040, 0x00000040, 0x10000000,
	0x00040040, 0x10040000, 0x10041040, 0x00041000,
	0x10041000, 0x00041040, 0x00001000, 0x00000040,
	0x10040000, 0x10000040, 0x10001000, 0x00001040,
	0x00041000, 0x00040040, 0x10040040, 0x10041000,
	0x00001040, 0x00000000, 0x00000000, 0x10040040,
	0x10000040, 0x10001000, 0x00041040, 0x00040000,
	0x00041040, 0x00040000, 0x10041000, 0x00001000,
	0x00000040, 0x10040040, 0x00001000, 0x00041040,
	0x10001000, 0x00000040, 0x10000040, 0x10040000,
	0x10040040, 0x10000000, 0x00040000, 0x10001040,
	0x00000000, 0x10041040, 0x00040040, 0x10000040,
	0x10040000, 0x10001000, 0x10001040, 0x00000000,
	0x10041040, 0x00041000, 0x00041000, 0x00001040,
	0x00001040, 0x00040040, 0x10000000, 0x10041000
};

static void des_crypt(uint32_t *block, const uint32_t *k)
{
	uint32_t r;
	uint32_t l;
	uint32_t t;
	unsigned int i;

	l = block[0];
	r = block[1];

	t = ((l >> 4) ^ r) & 0x0F0F0F0F;
	r ^= t;
	l ^= t << 4;
	t = ((l >> 16) ^ r) & 0x0000FFFF;
	r ^= t;
	l ^= t << 16;
	t = ((r >> 2) ^ l) & 0x33333333;
	l ^= t;
	r ^= t << 2;
	t = ((r >> 8) ^ l) & 0x00FF00FF;
	l ^= t;
	r ^= t << 8;
	r = ROL32_01(r);
	t = (l ^ r) & 0xAAAAAAAA;
	l ^= t;
	r ^= t;
	l = ROL32_01(l);

	for(i = 0; i < 8; i++)
	{
		t = ROR32_04(r) ^ *k++;
		l ^= SP7[t & 63]
			| SP5[(t >> 8) & 63]
			| SP3[(t >> 16) & 63]
			| SP1[(t >> 24) & 63];
		t = r ^ *k++;
		l ^= SP8[t & 63]
			| SP6[(t >> 8) & 63]
			| SP4[(t >> 16) & 63]
			| SP2[(t >> 24) & 63];

		t = ROR32_04(l) ^ *k++;
		r ^= SP7[t & 63]
			| SP5[(t >> 8) & 63]
			| SP3[(t >> 16) & 63]
			| SP1[(t >> 24) & 63];
		t = l ^ *k++;
		r ^= SP8[t & 63]
			| SP6[(t >> 8) & 63]
			| SP4[(t >> 16) & 63]
			| SP2[(t >> 24) & 63];
	}

	r = ROR32_01(r);
	t = (l ^ r) & 0xAAAAAAAA;
	l ^= t;
	r ^= t;
	l = ROR32_01(l);
	t = ((l >> 8) ^ r) & 0x00FF00FF;
	r ^= t;
	l ^= t << 8;
	t = ((l >> 2) ^ r) & 0x33333333;
	r ^= t;
	l ^= t << 2;
	t = ((r >> 16) ^ l) & 0x0000FFFF;
	l ^= t;
	r ^= t << 16;
	t = ((r >> 4) ^ l) & 0x0F0F0F0F;
	l ^= t;
	r ^= t << 4;

	block[0] = r;
	block[1] = l;
}

static void des_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	uint32_t block[2];

	block[0] = LOAD32B(CU8(pt));
	block[1] = LOAD32B(CU8(pt) + 4);

	des_crypt(block, *s->ek);

	if(s->tdes)
	{
		des_crypt(block, s->ek[1]);
		des_crypt(block, s->ek[2]);
	}

	STORE32B(block[0], U8(ct));
	STORE32B(block[1], U8(ct) + 4);
}

static void des_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	uint32_t block[2];

	block[0] = LOAD32B(CU8(ct));
	block[1] = LOAD32B(CU8(ct) + 4);

	des_crypt(block, *s->dk);

	if(s->tdes)
	{
		des_crypt(block, s->dk[1]);
		des_crypt(block, s->dk[2]);
	}

	STORE32B(block[0], U8(pt));
	STORE32B(block[1], U8(pt) + 4);
}

static kripto_block *des_create
(
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	kripto_block *s;

	(void)r;

	s = malloc(sizeof(kripto_block));
	if(!s) return 0;

	s->obj.desc = kripto_block_des;

	des_setup(s, key, key_len);

	return s;
}

static void des_destroy(kripto_block *s)
{
	kripto_memwipe(s, sizeof(kripto_block));
	free(s);
}

static kripto_block *des_recreate
(
	kripto_block *s,
	unsigned int r,
	const void *key,
	unsigned int key_len
)
{
	(void)r;

	des_setup(s, key, key_len);

	return s;
}

static const kripto_block_desc des =
{
	&des_create,
	&des_recreate,
	0, /* tweak */
	&des_encrypt,
	&des_decrypt,
	&des_destroy,
	8, /* block size */
	24, /* max key */
	0 /* max tweak */
};

const kripto_block_desc *const kripto_block_des = &des;
