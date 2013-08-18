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

#include <kripto/mac_desc.h>

#include <kripto/mac.h>

struct kripto_mac
{
	kripto_mac_desc *desc;
};

kripto_mac *kripto_mac_create
(
	kripto_mac_desc *desc,
	const void *f,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(desc);
	assert(desc->create);

	assert(key);
	assert(key_len);

	return desc->create(f, r, key, key_len, tag_len);
}

kripto_mac *kripto_mac_recreate
(
	kripto_mac *s,
	const void *f,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	unsigned int tag_len
)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->recreate);

	assert(key);
	assert(key_len);

	return s->desc->recreate(s, f, r, key, key_len, tag_len);
}

void kripto_mac_input(kripto_mac *s, const void *in, size_t len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->input);

	s->desc->input(s, in, len);
}

void kripto_mac_tag(kripto_mac *s, void *tag, unsigned int len)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->tag);

	s->desc->tag(s, tag, len);
}

void kripto_mac_destroy(kripto_mac *s)
{
	assert(s);
	assert(s->desc);
	assert(s->desc->destroy);

	s->desc->destroy(s);
}

int kripto_mac_all
(
	kripto_mac_desc *desc,
	const void *f,
	unsigned int r,
	const void *key,
	unsigned int key_len,
	const void *in,
	unsigned int in_len,
	void *tag,
	unsigned int tag_len
)
{
	kripto_mac *s;

	assert(desc);

	s = kripto_mac_create(desc, f, r, key, key_len, tag_len);
	if(!s) return -1;

	kripto_mac_input(s, in, in_len);
	kripto_mac_tag(s, tag, tag_len);

	kripto_mac_destroy(s);

	return 0;
}

kripto_mac_desc *kripto_mac_get_desc(const kripto_mac *s)
{
	assert(s);
	assert(s->desc);

	return s->desc;
}

unsigned int kripto_mac_max_tag(kripto_mac_desc *mac, const void *f)
{
	assert(mac);
	assert(mac->max_tag);

	return mac->max_tag(f);
}
