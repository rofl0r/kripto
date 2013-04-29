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
#include <string.h>
#include <stdlib.h>

#include <kripto/macros.h>
#include <kripto/memwipe.h>
#include <kripto/mac.h>

#include <kripto/pbkdf2.h>

int kripto_pbkdf2
(
	kripto_mac_desc mac_desc,
	void *f,
	const unsigned int iter,
	const void *pass,
	const unsigned int pass_len,
	const void *salt,
	const unsigned int salt_len,
	void *out,
	unsigned int out_len
)
{
	unsigned int i;
	unsigned int x;
	unsigned int y;
	uint32_t ctr = 1;
	uint8_t *buf[2];
	kripto_mac mac;

	x = kripto_mac_max(mac_desc, f);
	if(out_len < x) x = out_len;

	buf[0] = malloc(x << 1);
	if(!buf[0]) return -1;

	buf[1] = buf[0] + x;

	while(out_len)
	{
		U32TO8_BE(ctr, buf[1]);
		ctr++;

		mac = kripto_mac_create(mac_desc, f, pass, pass_len);
		if(!mac) goto err;

		if(kripto_mac_update(mac, salt, salt_len))
			goto err;

		if(kripto_mac_update(mac, buf[1], 4))
			goto err;

		if(kripto_mac_finish(mac, buf[0], x))
			goto err;

		kripto_mac_destroy(mac);

		memcpy(buf[1], buf[0], x);
		for(i = 1; i < iter; i++)
		{
			if(kripto_mac_all(mac_desc, f, pass, pass_len, buf[0], x, buf[0], x))
				goto err;

			for(y = 0; y < x; y++)
				buf[1][y] ^= buf[0][y];
		}

		/* output */
		for(y = 0; y < x && out_len; y++, out_len--)
		{
			*U8(out) = buf[1][y];
			PTR_INC(out, 1);
		}
	}

	//kripto_mac_destroy(mac);
	kripto_memwipe(buf[0], x << 1);
	free(buf[0]);

	return 0;

err:
	//kripto_mac_destroy(mac);
	kripto_memwipe(buf[0], x << 1);
	free(buf[0]);

	return -1;
}
