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

#include <assert.h>

#include <kripto/block_desc.h>

#include <kripto/block.h>

struct kripto_block
{
	const kripto_block_desc *desc;
};

kripto_block *kripto_block_create
(
	const kripto_block_desc *desc,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_block_maxkey(desc));

	return desc->create(rounds, key, key_len);
}

kripto_block *kripto_block_recreate
(
	kripto_block *s,
	unsigned int rounds,
	const void *key,
	unsigned int key_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);
	assert(key_len <= kripto_block_maxkey(s->desc));

	return s->desc->recreate(s, rounds, key, key_len);
}

void kripto_block_encrypt
(
	const kripto_block *s,
	const void *pt,
	void *ct
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->encrypt);
	assert(pt);
	assert(ct);

	s->desc->encrypt(s, pt, ct);
}

void kripto_block_decrypt
(
	const kripto_block *s,
	const void *ct,
	void *pt
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->decrypt);
	assert(ct);
	assert(pt);

	s->desc->decrypt(s, ct, pt);
}

void kripto_block_destroy(kripto_block *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

const kripto_block_desc *kripto_block_getdesc(const kripto_block *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_block_size(const kripto_block_desc *desc)
{
	assert(desc);
	assert(desc->blocksize);

	return desc->blocksize;
}

unsigned int kripto_block_maxkey(const kripto_block_desc *desc)
{
	assert(desc);
	assert(desc->maxkey);

	return desc->maxkey;
}
