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

#include <kripto/mac_desc.h>

#include <kripto/mac.h>

struct kripto_mac
{
	kripto_mac_desc desc;
};

kripto_mac kripto_mac_create
(
	kripto_mac_desc desc,
	void *f,
	const void *key,
	const unsigned int key_len
)
{
	return desc->create(f, key, key_len);
}

int kripto_mac_init
(
	kripto_mac s,
	void *f,
	const void *key,
	const unsigned int key_len
)
{
	return s->desc->init(s, f, key, key_len);
}

int kripto_mac_update(kripto_mac s, const void *in, const size_t len)
{
	return s->desc->update(s, in, len);
}

int kripto_mac_finish(kripto_mac s, void *out, const size_t len)
{
	return s->desc->finish(s, out, len);
}

void kripto_mac_destroy(kripto_mac s)
{
	s->desc->destroy(s);
}

kripto_mac_desc kripto_mac_get_desc(const kripto_mac s)
{
	return s->desc;
}
