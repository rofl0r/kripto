/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
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

#include <stdint.h>
#include <stdio.h>

#include <kripto/mac/hmac.h>
#include <kripto/hash/sha1.h>
#include <kripto/pbkdf2.h>

int main(void)
{
	const uint8_t out[20] =
	{
		0x4B, 0x00, 0x79, 0x01,
		0xB7, 0x65, 0x48, 0x9A,
		0xBE, 0xAD, 0x49, 0xD9,
		0x26, 0xF7, 0x21, 0xD0,
		0x65, 0xA4, 0x29, 0xC1
	};
	uint8_t buf[20];
	unsigned int i;

	if(kripto_pbkdf2
	(
		kripto_mac_hmac,
		kripto_hash_sha1,
		0,
		4096,
		"password",
		8,
		"salt",
		4,
		buf,
		20
	))
	{
		perror("kripto_pbkdf2() returned error");
		return -1;
	}

	for(i = 0; i < 20; i++) if(buf[i] != out[i])
	{
		fputs("kripto_pbkdf2: FAIL\n", stderr);
		return -1;
	}

	puts("kripto_pbkdf2: OK");
	return 0;
}
