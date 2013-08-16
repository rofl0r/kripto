#ifndef KRIPTO_BLOCK_DESC_H
#define KRIPTO_BLOCK_DESC_H

#include <kripto/block.h>

struct kripto_block_desc
{
	kripto_block *(*create)
	(
		const void *,
		unsigned int,
		unsigned int
	);
	kripto_block *(*recreate)
	(
		kripto_block *,
		const void *,
		unsigned int,
		unsigned int
	);
	void (*encrypt)(const kripto_block *, const void *, void *);
	void (*decrypt)(const kripto_block *, const void *, void *);
	void (*destroy)(kripto_block *);
	unsigned int block_size;
	unsigned int max_key;
};

#endif
