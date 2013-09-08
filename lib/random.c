/*
 * Copyright (C) 2012, 2013 Gregor Pintar <grpintar@gmail.com>
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

#include <assert.h>

#if defined(KRIPTO_UNIX)

#ifndef KRIPTO_DEV_RANDOM
#define KRIPTO_DEV_RANDOM "/dev/urandom"
#endif

#include <stdio.h>
#include <stdlib.h>

#elif defined(KRIPTO_WINDOWS)

#if !defined(KRIPTO_RTLGENRANDOM) && !defined(KRIPTO_CRYPTGENRANDOM)
#define KRIPTO_RTLGENRANDOM
#endif

#include <windows.h>

#if defined(KRIPTO_RTLGENRANDOM)
#include <stdlib.h>
struct kripto_random
{
	HMODULE lib;
	FARPROC rtlgenrandom;
};
#elif defined(KRIPTO_CRYPTGENRANDOM)
#include <wincrypt.h>
#endif

#else

#ifndef KRIPTO_RESEED_OUTPUT
#define KRIPTO_RESEED_OUTPUT 5242880 /* 5MB */
#endif

#ifndef KRIPTO_RESEED_TIME
#define KRIPTO_RESEED_TIME 300 /* 5 min */
#endif

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*#ifdef KRIPTO_UNIX
#include <sys/time.h>
#include <sys/resource.h>
#endif*/

#include <kripto/memwipe.h>
#include <kripto/stream.h>
#include <kripto/scrypt.h>
#include <kripto/stream/chacha.h>
#include <kripto/mac.h>
#include <kripto/mac.h>
#include <kripto/mac/hmac.h>
#include <kripto/hash.h>
#include <kripto/hash/blake2s.h>

struct kripto_random
{
	kripto_stream *stream;
	kripto_mac_desc *mac;
	time_t time;
	size_t output;
};

#endif

#include <kripto/random.h>

#if !defined(KRIPTO_WINDOWS) && !defined(KRIPTO_UNIX)

static int seed(kripto_random *s, uint8_t *out, unsigned int len)
{
	struct
	{
		#if defined(KRIPTO_UNIX)
		int pid;
		struct timespec time;
		struct rusage usage;
		#else
		time_t time;
		clock_t clock;
		#endif
		uint8_t unassigned[4];
	} entropy;

	s->mac = kripto_mac_hmac(kripto_hash_blake2s);
	if(!s->mac) return -1;

	#if defined(KRIPTO_UNIX)
	entropy.pid = getpid();
	(void)clock_gettime(CLOCK_REALTIME, &entropy.time);
	(void)getrusage(RUSAGE_SELF, &entropy.usage);
	#else
	entropy.time = time(NULL);
	entropy.clock = clock();
	#endif

	if(kripto_scrypt
	(
		s->mac, 0,
		1048576, 8, 1,
		&entropy, sizeof(entropy),
		0, 0,
		out, len
	)) return -1;

	memcpy(entropy.unassigned, &s, 4);

	#if defined(KRIPTO_UNIX)
	(void)clock_gettime(CLOCK_REALTIME, &entropy.time);
	(void)getrusage(RUSAGE_SELF, &entropy.usage);
	#else
	entropy.time = time(NULL);
	entropy.clock = clock();
	#endif

	if(kripto_scrypt
	(
		s->mac, 0,
		1048576, 8, 1,
		&entropy, sizeof(entropy),
		out, len,
		out, len
	)) return -1;

	kripto_memwipe(&entropy, sizeof(entropy));

	s->output = 0;
	s->time = time(NULL);

	return 0;
}

static kripto_random *create(void)
{
	kripto_random *s;
	uint8_t buf[32];

	s = malloc(sizeof(kripto_random));
	if(!s) return 0;

	if(seed(s, buf, 32)) goto err;

	s->stream = kripto_stream_create
	(
		kripto_stream_chacha, 0,
		buf, 32,
		0, 0
	);
	if(!s->stream) goto err;

	return s;

err:
	free(s);
	return 0;
}

#endif

kripto_random *kripto_random_create(void)
{
	#if defined(KRIPTO_DEV_RANDOM)

	const char *dev_random;
	/*FILE *fp;*/

	dev_random = getenv("KRIPTO_RANDOM");
	if(!dev_random)
		#ifdef KRIPTO_DEV_RANDOM
		dev_random = KRIPTO_DEV_RANDOM;
		#else
		return create();
		#endif

	return (kripto_random *)fopen(dev_random, "rb");

	/*fp = fopen(dev_random, "rb");
	if(fp) return (kripto_random *)fp;
	else return create();*/

	#elif defined(KRIPTO_RTLGENRANDOM)

	kripto_random *s;

	s = malloc(sizeof(kripto_random));
	if(!s) return 0;

	s->lib = LoadLibrary("advapi32.dll");
	if(!s->lib)
	{
		free(s);
		return 0;
	}

	s->rtlgenrandom = GetProcAddress(s->lib, "SystemFunction036");
	if(!s->rtlgenrandom)
	{
		FreeLibrary(s->lib);
		free(s);
		return 0;
	}

	return s;

	#elif defined(KRIPTO_CRYPTGENRANDOM)
	#if sizeof(kripto_random *) < sizeof(HCRYPTPROV)
	#error sizeof(kripto_random *) < sizeof(HCRYPTPROV)
	#endif

	HCRYPTPROV prov = 0;

	if(!CryptAcquireContext
	(
		&prov,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT
	)) return 0;

	return (kripto_random *)prov;

	#else

	return create();

	#endif
}

size_t kripto_random_gen(kripto_random *s, void *out, size_t len)
{
	assert(s);

	#if defined(KRIPTO_DEV_RANDOM)

	return fread(out, sizeof(char), len, (FILE *)s);

	#elif defined(KRIPTO_RTLGENRANDOM)

	assert(s->rtlgenrandom);
	if(s->rtlgenrandom(out, len) == TRUE) return len;
	return 0;
	
	#elif defined(KRIPTO_CRYPTGENRANDOM)

	if(CryptGenRandom((HCRYPTPROV)s, len, out)) return len;
	return 0;

	#else

	uint8_t buf[32];
	uint8_t iv[8];

	s->output += len;

	if /* reseed */
	(
		s->output > KRIPTO_RESEED_OUTPUT ||
		time(NULL) - s->time > KRIPTO_RESEED_TIME
	)
	{
		kripto_stream_prng(s->stream, iv, 8);

		if(seed(s, buf, 32)) goto err;

		s->stream = kripto_stream_recreate
		(
			s->stream, 0,
			buf, 32,
			iv, 8
		);
		if(!s->stream) goto err;
	}

	kripto_stream_prng(s->stream, out, len);

	return len;

err:
	kripto_memwipe(s, sizeof(kripto_random));
	free(s);
	return 0;

	#endif
}

void kripto_random_destroy(kripto_random *s)
{
	assert(s);

	#if defined(KRIPTO_DEV_RANDOM)

	fclose((FILE *)s);

	#elif defined(KRIPTO_RTLGENRANDOM)

	assert(s->lib);
	FreeLibrary(s->lib);

	#elif defined(KRIPTO_CRYPTGENRANDOM)

	CryptReleaseContext((HCRYPTPROV)s, 0);

	#else

	kripto_stream_destroy(s->stream);
	free(s->mac);

	kripto_memwipe(s, sizeof(kripto_random));
	free(s);

	#endif
}
