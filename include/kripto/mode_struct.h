#ifndef KRIPTO_MODE_STRUCT_H
#define KRIPTO_MODE_STRUCT_H

#include <stddef.h>

#include <kripto/block.h>
#include <kripto/stream.h>

struct kripto_mode
{
	kripto_stream (*create)
	(
		kripto_block,
		const void *,
		const unsigned int
	);
	unsigned int (*max_iv)(kripto_block_desc);
};

#endif
