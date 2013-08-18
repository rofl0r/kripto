/*
 * Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
 *
 * Permission is granted to deal in this work without any restriction,
 * including unlimited rights to use, publicly perform, publish,
 * reproduce, relicence, modify, merge, and/or distribute in any form,
 * for any purpose, with or without fee, and by any means.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
 * to the utmost extent permitted by applicable law. In no event
 * shall a licensor, author or contributor be held liable for any
 * issues arising in any way out of dealing in the work.
 */

#include <stddef.h>

#include <kripto/macros.h>

#include <kripto/pkcs7.h>

size_t kripto_pkcs7_add
(
	void *buf,
	size_t len,
	unsigned int pad,
	size_t maxlen
)
{
	unsigned int i;

	pad = pad - (len & (pad - 1));

	if(pad + len > maxlen) return 0;

	for(i = 0; i < pad; i++)
		U8(buf)[len + i] = pad;

	return (len + pad);
}

size_t kripto_pkcs7_rem(void *buf, size_t len)
{
	if(U8(buf)[len - 1] < len)
		return (len - U8(buf)[len - 1]);
	else
		return len;
}
