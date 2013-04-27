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

#include <kripto/stream.h>
#include <kripto/block.h>
#include <kripto/mode_struct.h>

#include <kripto/mode.h>

kripto_stream kripto_mode_create
(
	kripto_mode mode,
	kripto_block block,
	const void *iv,
	const unsigned int iv_len
)
{
	return mode->create(block, iv, iv_len);
}

unsigned int kripto_mode_max_iv(kripto_mode mode, kripto_block_desc block)
{
	return mode->max_iv(block);
}
