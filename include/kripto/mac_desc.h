#ifndef KRIPTO_MAC_DESC_H
#define KRIPTO_MAC_DESC_H

#include <kripto/mac.h>

struct kripto_mac_desc
{
	int (*init)
	(
		kripto_mac *,
		void *,
		const void *,
		const unsigned int
	);

	kripto_mac *(*create)
	(
		void *,
		const void *,
		const unsigned int
	);

	int (*update)(kripto_mac *, const void *, const size_t);
	int (*finish)(kripto_mac *, void *, const size_t);
	void (*destroy)(kripto_mac *);
	unsigned int (*max)(const void *);
};

#endif
