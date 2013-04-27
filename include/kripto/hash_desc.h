#ifndef KRIPTO_HASH_DESC_H
#define KRIPTO_HASH_DESC_H

#include <kripto/hash.h>

struct kripto_hash_desc
{
	void (*init)(kripto_hash, const size_t);
	int (*input)(kripto_hash, const void *, const size_t);
	void (*finish)(kripto_hash);
	int (*output)(kripto_hash, void *, const size_t);
	kripto_hash (*create)(const unsigned int, const size_t);
	void (*destroy)(kripto_hash);
	int (*hash_all)
	(
		const unsigned int,
		const void *,
		const size_t,
		void *,
		const size_t
	);
	unsigned int max;
	unsigned int block_size;
	unsigned int max_rounds;
	unsigned int default_rounds;
};

#endif
