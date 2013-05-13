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
	kripto_mac_desc *desc;
};

kripto_mac *kripto_mac_create
(
	kripto_mac_desc *desc,
	void *f,
	const void *key,
	const unsigned int key_len
)
{
	return desc->create(f, key, key_len);
}

int kripto_mac_update(kripto_mac *s, const void *in, const size_t len)
{
	return s->desc->update(s, in, len);
}

int kripto_mac_finish(kripto_mac *s, void *out, const size_t len)
{
	return s->desc->finish(s, out, len);
}

void kripto_mac_destroy(kripto_mac *s)
{
	s->desc->destroy(s);
}

int kripto_mac_all
(
	kripto_mac_desc *desc,
	void *f,
	const void *key,
	const unsigned int key_len,
	const void *in,
	const unsigned int in_len,
	void *out,
	const unsigned int out_len
)
{
	kripto_mac *s;

	s = kripto_mac_create(desc, f, key, key_len);
	if(!s) return -1;

	if(kripto_mac_update(s, in, in_len)) goto err;
	if(kripto_mac_finish(s, out, out_len)) goto err;

	kripto_mac_destroy(s);
	return 0;

err:
	kripto_mac_destroy(s);
	return -1;
}

kripto_mac_desc *kripto_mac_get_desc(const kripto_mac *s)
{
	return s->desc;
}

unsigned int kripto_mac_max(kripto_mac_desc *mac, const void *f)
{
	return mac->max(f);
}
