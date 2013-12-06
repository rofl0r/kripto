/*
 * Written in 2012 by Gregor Pintar <grpintar@gmail.com>
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

#include <stdint.h>
#include <string.h>
#include <math.h>

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

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L || \
	(defined(__cplusplus) && __cplusplus < 201103L)

#define LOG2(X) (log(X) / log(2))
#else
#define LOG2(X) log2(X)
#endif

static unsigned int bitcount(const uint8_t x)
{
	unsigned int c = 0;
	uint8_t mask;

	for(mask = 0x80; mask; mask >>= 1)
		if(x & mask) c++;

	return c;
}

static unsigned int bitflips(const uint8_t prev, const uint8_t x)
{
	unsigned int c = 0;
	uint8_t p = 0;
	uint8_t mask;

	p = prev;

	for(mask = 0x80; mask; mask >>= 1)
	{
		if(!p && (x & mask))
		{
			p = 1;
			c++;
		}
		else if(p && !(x & mask))
		{
			p = 0;
			c++;
		}
	}

	return c;
}

int kripto_random_test(kripto_random *s)
{
	uint8_t sample[4096];
	unsigned int count[256];
	uint8_t prev = 0;
	double ent = 0.0;
	double chi = 0.0;
	double avg = 0.0;
	double avg_null = 0.0;
	unsigned int bits = 0;
	unsigned int bit_flips = 0;

	/* distances */
	unsigned int dist[256];
	unsigned int dist_prev[256];
	unsigned int dist_zero = 0;

	/* serial correlation */
	double corr;
	double corr1 = 0;
	double corr2 = 0;
	double corr3 = 0;

	double t;
	unsigned int i;

	if(kripto_random_gen(s, sample, 4096) != 4096) return 0;

	memset(count, 0, sizeof(unsigned int) * 256);
	memset(dist, 0, sizeof(unsigned int) * 256);
	memset(dist_prev, 0, sizeof(unsigned int) * 256);

	for(i = 0; i < 4096; i++)
	{
		count[sample[i]]++;

		bits += bitcount(sample[i]);

		bit_flips += bitflips(prev & 1, sample[i]);

		/* distances */
		if(prev == sample[i]) dist_zero++;
		dist[sample[i]] += 4096 - dist_prev[sample[i]];
		dist_prev[sample[i]] = 4096;

		/* serial correlation */
		corr1 += prev * sample[i];
		corr2 += sample[i];
		corr3 += sample[i] * sample[i];

		prev = sample[i];
	}

	for(i = 0; i < 256; i++)
	{
		/* chi square */
		t = count[i] - 16;
		chi += t * t;

		/* entropy */
		t = (double)count[i] / 4096.0;
		if(t) ent -= t * LOG2(t);

		/* arithmetic mean */
		avg += i * count[i];

		/* average null distance */
		if(count[i]) avg_null += dist[i] / (double)count[i];
	}
	chi /= 16;
	avg /= 4096;

	/* serial correlation */
	corr2 = corr2 * corr2;
	corr = (double)(4096 * corr1 - corr2)
		/ (double)(4096 * corr3 - corr2);
	if(corr < 0.0) corr = -corr; /* absolute */

	/* check */
	if(ent < 7.9) return 0;
	if(avg < 125 || avg > 130.5) return 0;
	t = bits / 32768.0;
	if(t < 0.49 || t > 0.51) return 0;
	if(chi < 192 || chi > 320) return 0;
	t = bit_flips / 32768.0;
	if(t < 0.49 || t > 0.51) return 0;
	if(avg_null < 192 || avg_null > 320) return 0;
	if(dist_zero / 4096.0 > 0.1) return 0;
	if(corr > 0.1) return 0;

	return -1;
}
