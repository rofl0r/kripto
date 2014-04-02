#ifndef TEST_H
#define TEST_H

extern int test_result;

extern void test_pass(const char *test);

extern void test_fail(const char *test);

extern void test_error(const char *test);

extern void test_cmp
(
	const char *test,
	const void *s1,
	const void *s2,
	size_t len
);

#endif
