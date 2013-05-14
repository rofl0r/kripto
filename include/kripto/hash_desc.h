#ifndef KRIPTO_HASH_DESC_H
#define KRIPTO_HASH_DESC_H

#include <kripto/hash.h>

struct kripto_hash_desc
{
	void (*init)(kripto_hash *, const size_t);
	void (*input)(kripto_hash *, const void *, const size_t);
	void (*finish)(kripto_hash *);
	void (*output)(kripto_hash *, void *, const size_t);
	kripto_hash *(*create)(const size_t, const unsigned int);
	void (*destroy)(kripto_hash *);
	int (*hash_all)
	(
		const unsigned int,
		const void *,
		const size_t,
		void *,
		const size_t
	);
	size_t max_output;
	unsigned int block_size;
	unsigned int max_rounds;
	unsigned int default_rounds;
};

#endif
