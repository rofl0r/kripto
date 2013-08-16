#ifndef KRIPTO_AUTHSTREAM_DESC_H
#define KRIPTO_AUTHSTREAM_DESC_H

#include <stddef.h>

#include <kripto/authstream.h>

struct kripto_authstream_desc
{
	kripto_authstream *(*create)
	(
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int,
		const unsigned int
	);

	kripto_authstream *(*recreate)
	(
		kripto_authstream *,
		const void *,
		const unsigned int,
		const void *,
		const unsigned int,
		const unsigned int,
		const unsigned int
	);

	size_t (*encrypt)
	(
		kripto_authstream *,
		const void *,
		void *,
		const size_t
	);

	size_t (*decrypt)
	(
		kripto_authstream *,
		const void *,
		void *,
		const size_t
	);

	void (*tag)(kripto_authstream *, void *, const unsigned int);

	void (*destroy)(kripto_authstream *);

	unsigned int max_key;
	unsigned int max_iv;
	unsigned int max_tag;
};

#endif
