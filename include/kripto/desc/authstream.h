#ifndef KRIPTO_AUTHSTREAM_DESC_H
#define KRIPTO_AUTHSTREAM_DESC_H

#include <stddef.h>

#include <kripto/authstream.h>

struct kripto_authstream_desc
{
	kripto_authstream *(*create)
	(
		const kripto_authstream_desc *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	kripto_authstream *(*recreate)
	(
		kripto_authstream *,
		unsigned int,
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	void (*encrypt)
	(
		kripto_authstream *,
		const void *,
		void *,
		size_t
	);

	void (*decrypt)
	(
		kripto_authstream *,
		const void *,
		void *,
		size_t
	);

	void (*header)(kripto_authstream *, const void *, size_t);

	void (*tag)(kripto_authstream *, void *, unsigned int);

	void (*destroy)(kripto_authstream *);

	unsigned int maxkey;
	unsigned int maxiv;
	unsigned int maxtag;
};

#endif
