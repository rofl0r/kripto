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
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <kripto/cast.h>
#include <kripto/memwipe.h>
#include <kripto/mac.h>

#include <kripto/pbkdf2.h>

int kripto_pbkdf2
(
	const kripto_mac_desc *mac,
	unsigned int mac_rounds,
	unsigned int iter,
	const void *pass,
	unsigned int pass_len,
	const void *salt,
	unsigned int salt_len,
	void *out,
	size_t out_len
)
{
	unsigned int i;
	unsigned int x;
	unsigned int y;
	uint8_t ctr[4] = {0, 0, 0, 0};
	uint8_t *buf0;
	uint8_t *buf1;
	kripto_mac *m;

	assert(mac);
	assert(iter);

	x = kripto_mac_maxtag(mac);
	if(out_len < x) x = out_len;

	buf0 = malloc(x << 1);
	if(!buf0) return -1;

	buf1 = buf0 + x;

	m = kripto_mac_create(mac, mac_rounds, pass, pass_len, x);
	if(!m) goto err;

	for(;;)
	{
		for(i = 3; !++ctr[i]; i--)
			assert(i);

		kripto_mac_input(m, salt, salt_len);

		kripto_mac_input(m, ctr, 4);

		kripto_mac_tag(m, buf0, x);

		memcpy(buf1, buf0, x);

		for(i = 1; i < iter; i++)
		{
			m = kripto_mac_recreate(m, mac_rounds, pass, pass_len, x);
			if(!mac) goto err;

			kripto_mac_input(m, buf0, x);
			kripto_mac_tag(m, buf0, x);

			for(y = 0; y < x; y++)
				buf1[y] ^= buf0[y];
		}

		/* output */
		for(y = 0; y < x && out_len; y++, out_len--, out = U8(out) + 1)
			*U8(out) = buf1[y];

		if(!out_len) break;

		m = kripto_mac_recreate(m, mac_rounds, pass, pass_len, x);
		if(!m) goto err;
	}

	kripto_mac_destroy(m);
	kripto_memwipe(buf0, x);
	kripto_memwipe(buf1, x);
	free(buf0);

	return 0;

err:
	kripto_memwipe(buf0, x);
	kripto_memwipe(buf1, x);
	free(buf0);

	return -1;
}
