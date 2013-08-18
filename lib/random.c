/*
 * Copyright (C) 2012 Gregor Pintar <grpintar@gmail.com>
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
#elif defined(KRIPTO_CRYPTGENRANDOM)
#include <wincrypt.h>
#endif

#else

#error "Define OS (-DKRIPTO_UNIX or -DKRIPTO_WINDOWS)"

#include <kripto/stream.h>

#endif

#include <kripto/random.h>

#ifdef KRIPTO_RTLGENRANDOM

struct kripto_random
{
	HMODULE lib;
	FARPROC rtlgenrandom;
};

#endif

#include <assert.h>

kripto_random *kripto_random_create(void)
{
	#if defined(KRIPTO_DEV_RANDOM)

	const char *dev_random;

	dev_random = getenv("KRIPTO_RANDOM");
	if(!dev_random) dev_random = KRIPTO_DEV_RANDOM;

	return (kripto_random *)fopen(dev_random, "rb");

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

	if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
	CRYPT_VERIFYCONTEXT|CRYPT_SILENT)) return 0;

	return (kripto_random *)prov;

	#else

	return (kripto_random *)kripto_stream_create
	(
		kripto_stream_chacha,
		entropy,
		entropy_len,
		0, 0, 0
	);

	#endif
}

size_t kripto_random_get(kripto_random *s, void *out, size_t len)
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

	return kripto_stream_prng((kripto_stream *)s, out, size);

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

	kripto_stream_destroy((kripto_stream *)s);

	#endif
}
