/*
 * Copyright (C) 2013 Gregor Pintar <grpintar@gmail.com>
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

	// 369e24e2f11597d25cd8c8ab0b64e7bafa072fd5d23e1273a4cbdd95618b6296

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
