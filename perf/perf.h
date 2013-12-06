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

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <sched.h>
#include <unistd.h>

#if (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(__x86_64__))

inline uint64_t perf_clock(void)
{
	uint32_t hi;
	uint32_t lo;

	__asm__ __volatile__
	(
		"cpuid\n"
		"rdtsc"
		: "=a"(lo), "=d"(hi)
		: "a"(0)
		: "%ebx", "%ecx"
	);

	return (((uint64_t)hi) << 32) | lo;
}

#define PERF_START					\
{									\
	uint64_t t0;					\
	uint64_t t1;					\
	unsigned int i;					\
	cycles = UINT64_MAX;			\
	for(i = 0; i < 1000000; i++)	\
	{								\
		t0 = perf_clock();

#define PERF_STOP							\
		t1 = perf_clock() - t0 - perf_c;	\
		if(cycles > t1) cycles = t1;		\
	}										\
}

#else

#define PERF_START					\
{									\
	unsigned int i;					\
	cycles = clock();				\
	for(i = 0; i < 1000000; i++)	\
	{

#define PERF_STOP						\
	}									\
	cycles = (clock() - cycles) / 375;	\
}

#endif

uint64_t perf_c;

void perf_init(void)
{
	struct sched_param p;
	uint64_t cycles;

	puts("For better results disable dynamic CPU frequency scaling!");

	for(p.sched_priority = sched_get_priority_max(SCHED_FIFO);
		p.sched_priority; p.sched_priority--)
	{
		if(!sched_setscheduler(0, SCHED_FIFO, &p)) break;
	}

	PERF_START
	PERF_STOP
	perf_c = cycles;

	printf("SCHED_FIFO with priority: %u\n", p.sched_priority);
	putchar('\n');
}

void perf_rest(void)
{
	(void)sleep(1);
}
