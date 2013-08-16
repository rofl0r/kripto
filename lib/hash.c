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

#include <kripto/hash_desc.h>

#include <kripto/hash.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
};

kripto_hash *kripto_hash_create
(
	kripto_hash_desc *hash,
	const size_t len,
	const unsigned int r
)
{
	assert(hash);
	assert(hash->create);
	assert(len <= kripto_hash_max_output(hash));

	return hash->create(len, r);
}

kripto_hash *kripto_hash_recreate
(
	kripto_hash *s,
	const size_t len,
	const unsigned int r
)
{
	assert(s);
	assert(s->hash);
	assert(s->hash->recreate);
	assert(len <= kripto_hash_max_output(s->hash));

	return s->hash->recreate(s, len, r);
}

void kripto_hash_input(kripto_hash *s, const void *in, const size_t len)
{
	assert(s);
	assert(s->hash);
	assert(s->hash->input);

	s->hash->input(s, in, len);
}

void kripto_hash_output(kripto_hash *s, void *out, const size_t len)
{
	assert(s);
	assert(s->hash);
	assert(s->hash->output);
	assert(len <= kripto_hash_max_output(s->hash));

	s->hash->output(s, out, len);
}

void kripto_hash_destroy(kripto_hash *s)
{
	assert(s);
	assert(s->hash);
	assert(s->hash->destroy);

	s->hash->destroy(s);
}

int kripto_hash_all
(
	kripto_hash_desc *hash,
	const unsigned int r,
	const void *in,
	const size_t in_len,
	void *out,
	const size_t out_len
)
{
	assert(hash);
	assert(hash->hash_all);
	assert(out_len <= kripto_hash_max_output(hash));

	return hash->hash_all(r, in, in_len, out, out_len);
}

kripto_hash_desc *kripto_hash_get_desc(const kripto_hash *s)
{
	assert(s);
	assert(s->hash);

	return s->hash;
}

size_t kripto_hash_max_output(kripto_hash_desc *s)
{
	assert(s);
	assert(s->max_output);

	return s->max_output;
}

unsigned int kripto_hash_blocksize(kripto_hash_desc *s)
{
	assert(s);
	assert(s->block_size);

	return s->block_size;
}
