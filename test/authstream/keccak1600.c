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
#include <string.h>

#include <kripto/authstream.h>
#include <kripto/authstream/keccak1600.h>

int main(void)
{
	kripto_authstream *s;
	uint8_t t[32];
	const uint8_t pt[32] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	unsigned int i;

	// 369e24e2f1153d9482b1d697a8f22fdac4e66e908fe9fe4ca9fa9700c8623d64
	// 369e24e2f1157351d47f531b1f1809b872db51041f95e6640c5d9a4725f99002

	/* create */
	s = kripto_authstream_create(kripto_authstream_keccak1600, 0, pt, 16, pt, 16, 97);
	if(!s) perror("error");

	/* encrypt */
	//kripto_authstream_encrypt(s, pt, t, 32);
	kripto_authstream_encrypt(s, pt, t, 3);
	kripto_authstream_encrypt(s, pt + 3, t + 3, 29);

	for(i = 0; i < 32; i++) printf("%.2x", pt[i]);
	putchar('\n');

	for(i = 0; i < 32; i++) printf("%.2x", t[i]);
	putchar('\n');

	/* recreate */
	s = kripto_authstream_recreate(s, 0, pt, 16, pt, 16, 97);
	if(!s) perror("error");

	/* decrypt */
	//kripto_authstream_decrypt(s, t, t, 32);
	kripto_authstream_decrypt(s, t, t, 17);
	kripto_authstream_decrypt(s, t + 17, t + 17, 15);

	for(i = 0; i < 32; i++) printf("%.2x", t[i]);
	putchar('\n');

	if(memcmp(t, pt, 32)) puts("FAIL");
	else puts("OK");

	kripto_authstream_destroy(s);

	return 0;
}
