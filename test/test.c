/*
 * Written in 2014 by Gregor Pintar <grpintar@gmail.com>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "test.h"

int test_result = 0;

void test_pass(const char *test)
{
	(void)test;

	#ifdef VERBOSE
	fputs(test, stdout);
	puts(": PASS");
	#endif
}

void test_fail(const char *test)
{
	fputs(test, stdout);
	puts(": FAIL");
	//exit(1);
	test_result = 1;
}

void test_error(const char *test)
{
	perror(test);
	exit(-1);
	//test_result = -1;
}

void test_cmp(const char *test, const void *s1, const void *s2, size_t len)
{
	if(memcmp(s1, s2, len)) test_fail(test);
	else test_pass(test);
}
