#ifndef KRIPTO_MAC_DESC_H
#define KRIPTO_MAC_DESC_H

#include <kripto/mac.h>

struct kripto_mac_desc
{
	kripto_mac *(*create)
	(
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	kripto_mac *(*recreate)
	(
		kripto_mac *,
		const void *,
		unsigned int,
		const void *,
		unsigned int,
		unsigned int
	);

	void (*input)(kripto_mac *, const void *, size_t);
	void (*tag)(kripto_mac *, void *, unsigned int);
	void (*destroy)(kripto_mac *);
	unsigned int (*max_tag)(const void *);
};

#endif
