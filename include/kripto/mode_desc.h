#ifndef KRIPTO_MODE_DESC_H
#define KRIPTO_MODE_DESC_H

#include <stddef.h>

#include <kripto/block.h>
#include <kripto/stream.h>

struct kripto_mode_desc
{
	kripto_stream *(*create)
	(
		const kripto_block *,
		const void *,
		unsigned int
	);
	unsigned int (*max_iv)(kripto_block_desc *);
};

#endif
