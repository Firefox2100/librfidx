/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

extern const struct CMUnitTest *get_ntag21x_tests(size_t *count);
extern const struct CMUnitTest *get_ntag215_tests(size_t *count);
extern const struct CMUnitTest *get_mfc1k_tests(size_t *count);

extern const struct CMUnitTest *get_amiibo_tests(size_t *count);
extern const struct CMUnitTest *get_rfidx_tests(size_t *count);

struct CombinedTests {
    struct CMUnitTest *tests;
    size_t count;
};

struct CombinedTests combine_test_arrays(
    const struct CMUnitTest **arrays,
    const size_t *counts,
    const size_t num_arrays
) {
    size_t total = 0;
    for (size_t i = 0; i < num_arrays; ++i) {
        total += counts[i];
    }

    struct CMUnitTest *combined = malloc(sizeof(struct CMUnitTest) * total);
    size_t offset = 0;
    for (size_t i = 0; i < num_arrays; ++i) {
        memcpy(&combined[offset], arrays[i], sizeof(struct CMUnitTest) * counts[i]);
        offset += counts[i];
    }

    return (struct CombinedTests){.tests = combined, .count = total};
}

int main(const int argc, char **argv) {
    size_t ntag21x_count;
    size_t ntag215_count;
    size_t mfc1k_count;
    size_t amiibo_count;
    size_t rfidx_count;

    const struct CMUnitTest *ntag21x_tests = get_ntag21x_tests(&ntag21x_count);
    const struct CMUnitTest *ntag215_tests = get_ntag215_tests(&ntag215_count);
    const struct CMUnitTest *mfc1k_tests = get_mfc1k_tests(&mfc1k_count);
    const struct CMUnitTest *amiibo_tests = get_amiibo_tests(&amiibo_count);
    const struct CMUnitTest *rfidx_tests = get_rfidx_tests(&rfidx_count);

    const struct CMUnitTest *test_arrays[] = {
        ntag21x_tests,
        ntag215_tests,
        mfc1k_tests,
        amiibo_tests,
        rfidx_tests
    };
    const size_t test_counts[] = {
        ntag21x_count,
        ntag215_count,
        mfc1k_count,
        amiibo_count,
        rfidx_count
    };

    const struct CombinedTests combined_tests = combine_test_arrays(
        test_arrays,
        test_counts,
        sizeof(test_arrays) / sizeof(test_arrays[0])
    );

    const char *filter = NULL;
    if (argc > 1) {
        filter = argv[1];
    }

    struct CMUnitTest *filtered_tests = malloc(sizeof(struct CMUnitTest) * combined_tests.count);
    size_t filtered_count = 0;

    for (size_t i = 0; i < combined_tests.count; ++i) {
        if (!filter || strstr(combined_tests.tests[i].name, filter)) {
            filtered_tests[filtered_count++] = combined_tests.tests[i];
        }
    }

    if (filtered_count == 0) {
        fprintf(stderr, "No tests matched the filter: %s\n", filter ? filter : "no filter");
        free(filtered_tests);
        free(combined_tests.tests);
        return 1;
    }

    const int result = _cmocka_run_group_tests(
        "librfidx tests",
        filtered_tests,
        filtered_count,
        NULL,
        NULL
    );

    free(combined_tests.tests);

    return result;
}
