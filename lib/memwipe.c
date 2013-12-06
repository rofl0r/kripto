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
#include <stdint.h>

#include <kripto/memwipe.h>

void kripto_memwipe(void *dst, size_t len)
{
	volatile uint8_t *x = dst;

	while(len--) *x++ = '\0';
}
