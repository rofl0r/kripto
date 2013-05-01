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

#include <kripto/hash_desc.h>

#include <kripto/hash.h>

struct kripto_hash
{
	kripto_hash_desc *hash;
};

kripto_hash *kripto_hash_create
(
	kripto_hash_desc *hash,
	const unsigned int r,
	const size_t len
)
{
	return hash->create(r, len);
}

void kripto_hash_init(kripto_hash *s, const size_t len)
{
	s->hash->init(s, len);
}

int kripto_hash_input(kripto_hash *s, const void *in, const size_t len)
{
	return s->hash->input(s, in, len);
}

void kripto_hash_finish(kripto_hash *s)
{
	s->hash->finish(s);
}

int kripto_hash_output(kripto_hash *s, void *out, const size_t len)
{
	return s->hash->output(s, out, len);
}

void kripto_hash_destroy(kripto_hash *s)
{
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
	return hash->hash_all(r, in, in_len, out, out_len);
}

kripto_hash_desc *kripto_hash_get_desc(const kripto_hash *s)
{
	return s->hash;
}

unsigned int kripto_hash_max(kripto_hash_desc *s)
{
	return s->max;
}

unsigned int kripto_hash_blocksize(kripto_hash_desc *s)
{
	return s->block_size;
}
