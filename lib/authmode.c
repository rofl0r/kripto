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
#include <stdint.h>

#include <kripto/authstream.h>
#include <kripto/block.h>
#include <kripto/authmode_desc.h>

#include <kripto/authmode.h>

kripto_authstream *kripto_authmode_create
(
	kripto_authmode_desc *authmode,
	const kripto_block *block,
	const void *iv,
	const unsigned int iv_len,
	const unsigned int tag_len
)
{
	assert(authmode);
	assert(block);
	assert(authmode->create);
	if(iv_len) assert(iv);
	assert(tag_len <= kripto_authmode_max_tag(authmode, block));

	return authmode->create(block, iv, iv_len, tag_len);
}

unsigned int kripto_authmode_max_iv
(
	kripto_authmode_desc *authmode,
	kripto_block_desc *block
)
{
	assert(authmode);
	assert(block);
	assert(authmode->max_iv);

	return authmode->max_iv(block);
}

unsigned int kripto_authmode_max_tag
(
	kripto_authmode_desc *authmode,
	kripto_block_desc *block
)
{
	assert(authmode);
	assert(block);
	assert(authmode->max_tag);

	return authmode->max_tag(block);
}
