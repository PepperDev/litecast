/*
 * Mini unit-test framework. Each test file includes production .c files
 * directly; test files provide their own main().
 */

#ifndef LITECAST_TEST_UTIL_H
#define LITECAST_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>

static int test_failures;

#define EXPECT(cond)                                              \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,         \
                    __LINE__, #cond);                             \
            return -1;                                            \
        }                                                         \
    } while (0)

#define RUN(t)                                            \
    do {                                                  \
        int _r = (t)();                                   \
        printf("%s %s\n", _r ? "FAIL" : "ok", #t);        \
        test_failures += _r;                              \
    } while (0)

#define TEST_SUMMARY()                                              \
    do {                                                            \
        if (test_failures)                                          \
            printf("%d test(s) failed\n", test_failures);           \
        return test_failures ? EXIT_FAILURE : EXIT_SUCCESS;         \
    } while (0)

#define mock_sys_reset() do { } while (0)

#endif
