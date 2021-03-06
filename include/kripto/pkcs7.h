#ifndef KRIPTO_PKCS7_H
#define KRIPTO_PKCS7_H

#include <stddef.h>

extern size_t kripto_pkcs7_add
(
	void *buf,
	size_t len,
	unsigned int pad,
	size_t maxlen
);

extern size_t kripto_pkcs7_rem(void *buf, size_t len);

#endif
