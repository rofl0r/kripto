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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <kripto/macros.h>
#include <kripto/block.h>
#include <kripto/block_desc.h>
#include <kripto/mode.h>
#include <kripto/mode_ctr.h>
#include <kripto/stream.h>

struct kripto_block
{
	kripto_block_desc_t desc;
};

kripto_block_desc_t const kripto_block_dummy;

void dummy_crypt(const kripto_block s, const void *pt, void *ct)
{
	printf("%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n", U8(pt)[0], U8(pt)[1], U8(pt)[2], U8(pt)[3], U8(pt)[4], U8(pt)[5], U8(pt)[6], U8(pt)[7],U8(pt)[8], U8(pt)[9], U8(pt)[10], U8(pt)[11],U8(pt)[12], U8(pt)[13], U8(pt)[14], U8(pt)[15]);
	memcpy(ct, pt, 16);
}

kripto_block dummy_create(const void *key, unsigned int key_len, unsigned int r)
{
	kripto_block s;

	s = malloc(sizeof(struct kripto_block));
	s->desc = kripto_block_dummy;

	return s;
}

void dummy_destroy(kripto_block s)
{
	free(s);
}

const struct kripto_block_desc dummy =
{
	&dummy_crypt,
	&dummy_crypt,
	&dummy_create,
	&dummy_destroy,
	16,
	0,
	0,
	0
};

kripto_block_desc_t const kripto_block_dummy = &dummy;

int main(void)
{
	kripto_stream_t s;
	kripto_block_t b;
	char buf[640];

	b = kripto_block_create(kripto_block_dummy, "987654321", 8, 0);
	if(b) puts("BLOCK CREATED");
	s = kripto_mode_create(kripto_mode_ctr, b, "123456789", 8);
	if(s) puts("MODE CREATED");
	kripto_stream_prng(s, buf, 640);

	return 0;
}
