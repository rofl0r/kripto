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

#include <kripto/macros.h>

#include <kripto/mode_cbc.h>

size_t kripto_mode_cbc_encrypt(kripto_mode_cbc_t *s, const void *pt, void *ct, size_t len)
{
	size_t i;
	unsigned int n;

	if(len & (kripto_block_size(s->cipher) - 1)) return(0);

	for(i = 0; i < len; i += n)
	{
		/* count output */
		/*for(n = 0; n < (kripto_block_size(s->cipher) >> 1); n += sizeof(size_t))
		{
			if(++s->count[n])
			{
				if(n == (s->block_size >> 1)) return(i);
				break;
			}
		}*/

		for(n = 0; n < kripto_block_size(s->cipher); n++)
			U8(ct)[n] = CU8(pt)[n] ^ s->iv[n];

		kripto_block_encrypt(s->cipher, ct, ct);

		for(n = 0; n < kripto_block_size(s->cipher); n++)
			s->iv[n] = U8(ct)[n];

		PTR_INC(pt, n);
		PTR_INC(ct, n);
	}

	return(i);
}

size_t kripto_mode_cbc_decrypt(kripto_mode_cbc_t *s, const void *ct, void *pt, size_t len)
{
	size_t i;
	unsigned int n;

	if(len & (kripto_block_size(s->cipher) - 1)) return(0);

	for(i = 0; i < len; i += n)
	{
		for(n = 0; n < kripto_block_size(s->cipher); n++)
			s->t[n] = CU8(ct)[n];

		kripto_block_decrypt(s->cipher, ct, pt);

		for(n = 0; n < kripto_block_size(s->cipher); n++)
		{
			U8(pt)[n] ^=  s->iv[n];
			s->iv[n] = s->t[n];
		}

		PTR_INC(ct, n);
		PTR_INC(pt, n);
	}

	return(i);
}

size_t kripto_mode_cbc_prng(kripto_mode_cbc_t *s, const void *ct, void *pt, size_t len)
{
	return(0);
}

#include <string.h>

void kripto_mode_cbc_setup(kripto_mode_cbc_t *s, const kripto_block_t *cipher, const void *iv)
{
	s->desc = &kripto_mode_cbc_desc;
	s->cipher = cipher;
	memcpy(s->iv, iv, kripto_block_size(cipher));
}

#include <stdlib.h>

kripto_mode_cbc_t *kripto_mode_cbc_new(const kripto_block_t *cipher, const void *iv, unsigned int iv_len)
{
	kripto_mode_cbc_t *s;

	if(iv_len != kripto_block_size(cipher)) return(0);

	s = malloc(sizeof(kripto_mode_cbc_t) + (kripto_block_size(cipher) << 1));
	if(!s) return(0);
	s->iv = (uint8_t *)s + sizeof(kripto_mode_cbc_t);
	s->t = s->iv + kripto_block_size(cipher);

	kripto_mode_cbc_setup(s, cipher, iv);

	return(s);
}

#include <kripto/memwipe.h>

void kripto_mode_cbc_delete(kripto_mode_cbc_t *s)
{
	kripto_memwipe(s, sizeof(kripto_mode_cbc_t) + (kripto_block_size(s->cipher) << 1));
	free(s);
}

const kripto_desc_mode_t kripto_mode_cbc_desc =
{
	&kripto_mode_cbc_encrypt,
	&kripto_mode_cbc_decrypt,
	&kripto_mode_cbc_prng,
	&kripto_mode_cbc_new,
	&kripto_mode_cbc_delete
};
