/*
 * Written in 2011 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stddef.h>

#include <kripto/cast.h>

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
