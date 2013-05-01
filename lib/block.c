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

#include <kripto/block_desc.h>

#include <kripto/block.h>

struct kripto_block
{
	kripto_block_desc *desc;
};

kripto_block *kripto_block_create
(
	kripto_block_desc *desc,
	const void *key,
	const unsigned int key_len,
	const unsigned int r
)
{
	return desc->create(key, key_len, r);
}

void kripto_block_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	s->desc->encrypt(s, pt, ct);
}

void kripto_block_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	s->desc->decrypt(s, ct, pt);
}

void kripto_block_destroy(kripto_block *s)
{
	s->desc->destroy(s);
}

kripto_block_desc *kripto_block_get_desc(const kripto_block *s)
{
	return s->desc;
}

unsigned int kripto_block_size(kripto_block_desc *desc)
{
	return desc->block_size;
}

unsigned int kripto_block_max_key(kripto_block_desc *desc)
{
	return desc->max_key;
}

unsigned int kripto_block_max_rounds(kripto_block_desc *desc)
{
	return desc->max_rounds;
}

unsigned int kripto_block_default_rounds(kripto_block_desc *desc)
{
	return desc->default_rounds;
}
