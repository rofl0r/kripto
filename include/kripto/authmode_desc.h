#ifndef KRIPTO_AUTHMODE_DESC_H
#define KRIPTO_AUTHMODE_DESC_H

#include <stddef.h>

#include <kripto/block.h>
#include <kripto/authstream.h>

struct kripto_authmode_desc
{
	kripto_authstream *(*create)
	(
		const kripto_block *,
		const void *,
		unsigned int,
		unsigned int
	);
	unsigned int (*max_iv)(kripto_block_desc *);
	unsigned int (*max_tag)(kripto_block_desc *);
};

#endif
